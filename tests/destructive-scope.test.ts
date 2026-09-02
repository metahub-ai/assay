/**
 * no-unguarded-destructive-ops.
 *
 * Half the cases below prove it catches an unguarded bulk-delete;
 * the other half prove it leaves a guarded or merely-mentioned one
 * alone. Per CONTRIBUTING.md, the second half is the one that
 * matters more — a check that cries wolf on correct, careful code
 * gets disabled, and then it protects nobody.
 */
import { describe, expect, it } from "vitest";
import { noUnguardedDestructiveOps } from "../src/checks/destructive-scope";
import type { CheckContext, CheckDefinition } from "../src/check";
import type { CheckResult, Subject } from "../src/types";
import { MemorySource } from "../src/sources/memory";

const subject: Subject = {
  kind: "skill",
  name: "demo",
  source: { type: "directory", path: "/tmp/demo" },
  digest: { sha256: "0".repeat(64) },
};

function ctxFor(files: Record<string, string>): CheckContext {
  const noop = () => {};
  return {
    subject,
    source: new MemorySource(files),
    config: {},
    log: { debug: noop, info: noop, warn: noop, error: noop },
    signal: new AbortController().signal,
  };
}

const run = (check: CheckDefinition, ctx: CheckContext): Promise<CheckResult> =>
  Promise.resolve(check.run(ctx));

describe("no-unguarded-destructive-ops", () => {
  it("skips an artifact with no source files", async () => {
    const r = await run(noUnguardedDestructiveOps, ctxFor({ "README.md": "hello" }));
    expect(r.status).toBe("skip");
  });

  it("is neutral on ordinary code with no destructive shapes", async () => {
    const r = await run(
      noUnguardedDestructiveOps,
      ctxFor({ "index.js": "function add(a, b) { return a + b; }\n" }),
    );
    expect(r.status).toBe("neutral");
  });

  it.each([
    [
      "an unguarded Gmail batch delete",
      "index.js",
      "async function clear(ids) {\n  await gmail.users.messages.batchDelete({ userId: 'me', ids });\n}\n",
    ],
    ["an unguarded recursive rm -rf", "cleanup.sh", '#!/bin/bash\nrm -rf "$TARGET_DIR"\n'],
    [
      "an unguarded shutil.rmtree",
      "cleanup.py",
      "import shutil\ndef wipe(path):\n    shutil.rmtree(path)\n",
    ],
    ["an unguarded DROP TABLE", "migrate.rb", "def down\n  execute('DROP TABLE users')\nend\n"],
    [
      "an unguarded Prisma deleteMany",
      "reset.ts",
      "export async function resetAll() {\n  await prisma.record.deleteMany({});\n}\n",
    ],
  ])("warns on %s", async (_label, path, code) => {
    const r = await run(noUnguardedDestructiveOps, ctxFor({ [path]: code }));
    expect(r.status).toBe("warn");
    expect(r.evidence?.[0]).toMatchObject({ type: "file", path });
  });

  it("passes a batch delete guarded by an explicit confirmation prompt", async () => {
    const code = [
      "async function clear(ids) {",
      "  const ok = await confirm(`Delete ${ids.length} messages? This cannot be undone.`);",
      "  if (!ok) return;",
      "  await gmail.users.messages.batchDelete({ userId: 'me', ids });",
      "}",
      "",
    ].join("\n");
    const r = await run(noUnguardedDestructiveOps, ctxFor({ "index.js": code }));
    expect(r.status).toBe("pass");
  });

  it("passes a recursive delete guarded by a dry-run flag", async () => {
    const code = [
      "#!/bin/bash",
      "# usage: cleanup.sh [--dry-run]",
      'if [ "$1" = "--dry-run" ]; then',
      '  echo would rm -rf "$TARGET_DIR"',
      "else",
      '  rm -rf "$TARGET_DIR"',
      "fi",
      "",
    ].join("\n");
    const r = await run(noUnguardedDestructiveOps, ctxFor({ "cleanup.sh": code }));
    expect(r.status).toBe("pass");
  });

  it("does not flag documentation that merely mentions the pattern", async () => {
    // Same shape of prose false positive CONTRIBUTING.md calls out for
    // no-dynamic-code-execution: a doc FILE mentioning `rm -rf` in
    // English is not code, and code.ts's FIXTURE filter excludes .md
    // and docs/ entirely. Mirror that here.
    const r = await run(
      noUnguardedDestructiveOps,
      ctxFor({ "docs/README.md": "Do not run `rm -rf` on your home directory.\n" }),
    );
    expect(r.status).toBe("skip");
  });

  it("does not flag a single-record, non-bulk delete", async () => {
    // A routine ORM `delete()` on one record is not the shape this
    // check targets — only unscoped/bulk operations are, per the
    // pattern table (deleteMany, batchDelete, TRUNCATE, DROP TABLE,
    // rm -rf, rmtree). This proves the check does not over-match.
    const code = "async function removeUser(id) {\n  await db.user.delete({ where: { id } });\n}\n";
    const r = await run(noUnguardedDestructiveOps, ctxFor({ "index.ts": code }));
    expect(r.status).toBe("neutral");
  });

  it("mixed file: reports only the unguarded hit when one of two is guarded", async () => {
    // The two calls are kept far enough apart (well beyond
    // CONTEXT_LINES) that each hit's proximity window is independent —
    // this is what distinguishes "unguarded" from "guarded" rather than
    // one guard word anywhere in the file blessing every call in it.
    const filler = Array.from({ length: 10 }, (_, i) => `// unrelated line ${i}`).join("\n");
    const code = [
      "async function purgeAll(ids) {",
      "  await gmail.users.messages.batchDelete({ userId: 'me', ids });", // unguarded
      "}",
      filler,
      "async function purgeConfirmed(ids) {",
      "  const ok = await confirm('are you sure?');",
      "  if (!ok) return;",
      "  await gmail.users.messages.batchDelete({ userId: 'me', ids });", // guarded
      "}",
      "",
    ].join("\n");
    const r = await run(noUnguardedDestructiveOps, ctxFor({ "mixed.js": code }));
    expect(r.status).toBe("warn");
    expect(r.summary).toContain("1 of 2");
  });
});
