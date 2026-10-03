/**
 * Destructive operations without a declared, guarded scope.
 *
 * `skill-allowed-tools` (kinds/skill.ts) checks whether a SCOPE was
 * declared at all. It cannot see whether the code behind that scope
 * does anything irreversible — a skill can declare `allowed-tools: []`
 * and still ship a function that calls a bulk-delete API the moment a
 * client grants it broader access anyway, which happens today because
 * `allowed-tools` is advisory, not enforced by most clients.
 *
 * This check looks at the code itself: does it call an API shape that
 * is bulk, irreversible, or both (mailbox purges, recursive filesystem
 * deletes, unscoped table drops), and if so, is there anything next to
 * it — a dry-run flag, a confirmation prompt, an explicit allowlist —
 * that gives a consumer a chance to stop it before it runs? An
 * artifact that deletes without ever asking is a different risk than
 * one that deletes after a confirmation step, and a listing should say
 * which one a consumer is installing.
 */
import { defineCheck } from "../check.js";
import type { CheckContext } from "../check.js";
import type { CheckResult, Evidence } from "../types.js";
import { checkSpecUrl } from "../version.js";

/** Files worth reading. Mirrors code.ts's language coverage. */
const CODE = /\.(m?[jt]sx?|py|rb|sh|bash|zsh|go|rs|java|kt|cs|php|swift)$/i;
const SKIP = /(^|\/)(node_modules|\.git|vendor|__pycache__|dist|build)\//;
const FIXTURE =
  /(^|\/)(tests?|__tests__|fixtures?|examples?|samples?|spec|docs?)\/|\.(test|spec|example|sample)\.[a-z]+$/i;

const MAX_FILES = 400;
const MAX_BYTES = 512 * 1024;

/**
 * Bulk or irreversible operation shapes.
 *
 * Deliberately named APIs and idioms rather than single verbs — a bare
 * `delete` matches too much prose and too many single-record ORM calls
 * that are routine and reversible-by-database-backup. Each pattern
 * here is a shape whose ordinary reading is "remove many things" or
 * "remove permanently, now."
 */
const DESTRUCTIVE: { pattern: RegExp; what: string }[] = [
  { pattern: /\bbatchDelete\b/, what: "a batch-delete call" },
  {
    pattern: /\busers\.messages\.trash\b|\busers\.messages\.delete\b/,
    what: "a Gmail message delete/trash call",
  },
  { pattern: /\brm\s+-rf\b/, what: "a recursive forced filesystem delete" },
  { pattern: /\bshutil\.rmtree\b/, what: "a recursive directory delete" },
  { pattern: /\bDROP\s+TABLE\b/i, what: "a DROP TABLE statement" },
  { pattern: /\bTRUNCATE\s+TABLE\b/i, what: "a TRUNCATE TABLE statement" },
  { pattern: /\.deleteMany\s*\(/, what: "an unscoped bulk delete (deleteMany)" },
  { pattern: /\bpurge(?:Inbox|Mailbox|Messages)\b/i, what: "an inbox/mailbox purge call" },
];

/**
 * Signals that a destructive call is guarded rather than unconditional.
 *
 * Deliberately loose: this is a coarse proximity heuristic, not a data-
 * flow analysis. The point is not to prove the guard actually reaches
 * the call — that needs real static analysis this check does not do —
 * it is to tell "nothing here even gestures at confirmation" apart from
 * "there is a dry-run flag two lines up," which is worth a different
 * verdict even on a heuristic look.
 */
const GUARD = /\bdry.?run\b|\bconfirm(?:ation)?\b|\byes.?to.?all\b|\b--force\b|\bare.?you.?sure\b/i;

/** How many lines around a hit count as "next to it". */
const CONTEXT_LINES = 5;

interface Hit {
  path: string;
  line: number;
  what: string;
  guarded: boolean;
}

async function scan(ctx: CheckContext): Promise<{ hits: Hit[]; scanned: number }> {
  const tree = await ctx.source.listTree();
  const files = tree
    .filter(
      (e) => e.type === "file" && CODE.test(e.path) && !SKIP.test(e.path) && !FIXTURE.test(e.path),
    )
    .slice(0, MAX_FILES);

  const hits: Hit[] = [];
  let scanned = 0;
  for (const f of files) {
    if ((f.size ?? 0) > MAX_BYTES) continue;
    const body = await ctx.source.readFile(f.path);
    if (body === null) continue;
    scanned++;
    const lines = body.split("\n");
    for (let i = 0; i < lines.length; i++) {
      for (const { pattern, what } of DESTRUCTIVE) {
        if (!pattern.test(lines[i])) continue;
        const start = Math.max(0, i - CONTEXT_LINES);
        const end = Math.min(lines.length, i + CONTEXT_LINES + 1);
        const window = lines.slice(start, end).join("\n");
        hits.push({ path: f.path, line: i + 1, what, guarded: GUARD.test(window) });
      }
    }
  }
  return { hits, scanned };
}

export const noUnguardedDestructiveOps = defineCheck({
  id: "no-unguarded-destructive-ops",
  version: "1.0.0",
  title: "Destructive operations are guarded",
  category: "safety",
  axis: "safety",
  determinism: "deterministic",
  // Landing at weight 0 (informational) per CONTRIBUTING.md: this is a
  // proximity heuristic, not a data-flow proof, and a new check earns
  // score-affecting weight only after real fixtures show its false-
  // positive rate is low enough to trust with somebody else's grade.
  weight: 0,
  blocking: false,
  spec: checkSpecUrl("no-unguarded-destructive-ops"),
  inspects: "Source files for bulk-delete, purge, and irreversible-operation call shapes.",
  rationale:
    "A skill or server that can silently delete data at scale — a mailbox purge, a recursive filesystem delete, an unscoped table drop — is a materially different risk from one that cannot, and nothing about a declared tool scope tells a consumer whether the code behind it asks before it acts. This does not block: false positives here (a legitimate cleanup script, a well-guarded admin tool) cost the publisher, so it warns and asks for evidence a human can check, rather than failing a build on a heuristic.",
  examples: {
    passing:
      'if (dryRun || (await confirm("delete all matching messages?"))) await batchDelete(ids);',
    failing: "await gmail.users.messages.batchDelete({ userId: 'me', ids: allIds });",
  },
  async run(ctx): Promise<CheckResult> {
    const { hits, scanned } = await scan(ctx);
    if (scanned === 0) return { status: "skip", summary: "No source files to scan." };
    if (hits.length === 0) {
      return { status: "neutral", summary: "No bulk or irreversible operation patterns found." };
    }

    const unguarded = hits.filter((h) => !h.guarded);
    if (unguarded.length === 0) {
      return {
        status: "pass",
        summary: `Found ${hits.length} destructive call(s); each has a confirmation or dry-run signal nearby.`,
        evidence: hits
          .slice(0, 10)
          .map((h): Evidence => ({ type: "file", path: h.path, line: h.line })),
      };
    }

    return {
      status: "warn",
      summary: `${unguarded.length} of ${hits.length} destructive call(s) have no nearby confirmation, dry-run, or force flag.`,
      detail:
        "This is a proximity heuristic over the surrounding lines, not a data-flow proof that a guard reaches the call — read the listed lines before acting on this finding either way.",
      remediation:
        "Gate the destructive call behind an explicit confirmation step or a dry-run mode that defaults to on, and say so in the artifact's documentation so a consumer can see it without reading the code.",
      evidence: unguarded.slice(0, 10).map((h): Evidence => ({
        type: "file",
        path: h.path,
        line: h.line,
        excerpt: h.what,
      })),
    };
  },
});

export const DESTRUCTIVE_SCOPE_CHECKS = [noUnguardedDestructiveOps];
