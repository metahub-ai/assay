/**
 * Checks that read code as code, not as lines of text.
 *
 * The content checks in `content.ts` match patterns against individual
 * lines. That catches the careless and misses anyone who has read a
 * blog post. An artifact carrying a split credential, a base64 payload
 * behind `eval`, a hardcoded exfiltration address and a shell-out to a
 * raw IP scored **96.1 with safety at 100** — because every one of
 * those is invisible to a line-oriented regex.
 *
 * These four close that gap. The design constraint throughout is
 * precision: this catalog has already had to narrow eight checks that
 * were confidently wrong about correct work, and a safety check that
 * cries wolf gets disabled, at which point it protects nobody. So each
 * one here looks for a SHAPE that has no innocent reading, and where a
 * benign explanation exists the finding warns rather than blocks.
 */
import { defineCheck } from "../check.js";
import type { CheckContext } from "../check.js";
import type { CheckResult, Evidence } from "../types.js";
import { isPlaceholder } from "./content.js";
import { checkSpecUrl } from "../version.js";

/**
 * Source files worth parsing.
 *
 * Deliberately broad. This used to be JS, Python, Ruby and shell, which
 * meant the entire code-safety suite was blind to everything else — a
 * Go MCP server shelling out to `curl … | bash` scored safety 92.9 and
 * was not blocked. MCP is a protocol and skills are prose; neither
 * implies an ecosystem, and GitHub's own MCP server is Go.
 *
 * Three of the four code checks — egress, assembled credentials,
 * obfuscated payloads — are language-agnostic: they look for URLs,
 * concatenated literals and encoded blobs, which look the same in any
 * syntax. Widening the file filter gives those checks coverage
 * everywhere immediately. Only dynamic execution needs per-language
 * patterns, and a language without them simply does not run that one.
 */
const CODE =
  /\.(m?[jt]sx?|py|rb|sh|bash|zsh|go|rs|java|kt|cs|php|swift|c|cc|cpp|h|hpp|lua|pl|ps1)$/i;

/** Never code we are grading. */
const SKIP = /(^|\/)(node_modules|\.git|vendor|__pycache__)\//;

/** Build output — sometimes a duplicate, sometimes the whole artifact. */
const BUILT = /(^|\/)(dist|build|out)\//;

/**
 * Whether build output should be read.
 *
 * In a source repository `dist/` is a generated copy, and scanning it
 * reports every finding twice. In a published npm tarball there is no
 * source at all — `dist/` IS the artifact, and skipping it means the
 * check reports "no source files to read" for precisely the packages a
 * consumer actually installs. So the rule is not the directory name
 * but whether a source alternative exists.
 */
export function skips(tree: ReadonlyArray<{ type: string; path: string }>): (p: string) => boolean {
  const hasSource = tree.some(
    (e) =>
      e.type === "file" &&
      !SKIP.test(e.path) &&
      !BUILT.test(e.path) &&
      /\.(m?[jt]sx?|py|rb)$/i.test(e.path),
  );
  return (p) => SKIP.test(p) || (hasSource && BUILT.test(p));
}

/**
 * A bundled or minified file.
 *
 * Its contents are usually somebody else's code, inlined by a build
 * tool. A `new Function` inside a webpack bundle is real, but blaming
 * the publisher for it is how a check earns a reputation for lying, so
 * these findings are reported without blocking.
 */
function isMinified(body: string): boolean {
  let longest = 0;
  for (const line of body.split("\n")) if (line.length > longest) longest = line.length;
  return longest > 1000;
}

/**
 * Files whose whole job is to contain these patterns.
 *
 * A security tool's own test fixtures and its documentation are the
 * two places a payload legitimately appears as data.
 */
const FIXTURE =
  /(^|\/)(tests?|__tests__|fixtures?|examples?|samples?|spec|docs?)\/|\.(test|spec|example|sample)\.[a-z]+$|\.md$/i;

const MAX_FILES = 400;
const MAX_BYTES = 512 * 1024;

interface Hit {
  path: string;
  line: number;
  what: string;
  /** Found inside a bundle, so probably not code the publisher wrote. */
  minified?: boolean;
}

/** Iterate the artifact's own source files. */
async function eachFile(
  ctx: CheckContext,
  visit: (path: string, body: string, minified: boolean) => void,
): Promise<number> {
  const tree = await ctx.source.listTree();
  const skip = skips(tree);
  const files = tree
    .filter((e) => e.type === "file" && CODE.test(e.path) && !skip(e.path) && !FIXTURE.test(e.path))
    .slice(0, MAX_FILES);
  let scanned = 0;
  for (const f of files) {
    if ((f.size ?? 0) > MAX_BYTES) continue;
    const body = await ctx.source.readFile(f.path);
    if (body === null) continue;
    scanned++;
    visit(f.path, body, isMinified(body));
  }
  return scanned;
}

/**
 * Line ranges that are test code living inside a production file.
 *
 * `skips()` excludes files NAMED like tests, which is enough for
 * ecosystems that keep tests in separate files. Rust does not: the
 * convention is an inline `#[cfg(test)] mod tests { … }` at the bottom
 * of the module it tests, so the test code sits in a file that is
 * unambiguously production source.
 *
 * That gap blocked a published artifact on this line:
 *
 *   assert!(!is_loopback_http_url(&parsed("http://192.168.1.2:8080/v1")))
 *
 * — a unit test asserting that a private address is correctly REJECTED.
 * The artifact was flagged for undeclared egress because it tests the
 * exact hardening the check wants to see. Blaming a publisher for
 * testing their own defences is the fastest way to teach them the
 * score is noise.
 */
function testScopeOf(path: string, lines: readonly string[]): (i: number) => boolean {
  if (!/\.rs$/i.test(path)) return () => false;

  const ranges: Array<[number, number]> = [];
  for (let i = 0; i < lines.length; i++) {
    if (!/^\s*#\[cfg\(test\)\]/.test(lines[i]!)) continue;
    // Walk forward tracking braces until the module closes. Counting
    // braces is crude but the alternative is parsing Rust, and the
    // failure mode here is only ever "skipped a few extra lines of a
    // test module" rather than a missed finding in real code.
    let depth = 0;
    let opened = false;
    let j = i + 1;
    for (; j < lines.length; j++) {
      for (const ch of lines[j]!) {
        if (ch === "{") {
          depth++;
          opened = true;
        } else if (ch === "}") depth--;
      }
      if (opened && depth <= 0) break;
    }
    ranges.push([i, Math.min(j, lines.length - 1)]);
  }
  if (ranges.length === 0) return () => false;
  return (i) => ranges.some(([a, b]) => i >= a && i <= b);
}

async function scan(
  ctx: CheckContext,
  match: (line: string, path: string, all: string[], i: number) => string | null,
): Promise<{ hits: Hit[]; scanned: number }> {
  const hits: Hit[] = [];
  const scanned = await eachFile(ctx, (path, body, minified) => {
    const lines = body.split("\n");
    // Computed once per file rather than per line — it walks the whole
    // file, and doing that 40,000 times over a large source tree is the
    // difference between a fast check and a slow one.
    const inTestScope = testScopeOf(path, lines);
    for (let i = 0; i < lines.length; i++) {
      if (inTestScope(i)) continue;
      const what = match(lines[i]!, path, lines, i);
      if (what) hits.push({ path, line: i + 1, what, ...(minified ? { minified: true } : {}) });
    }
  });
  return { hits, scanned };
}

/**
 * Split findings into those the publisher is answerable for and those
 * a bundler inlined. Only the former blocks.
 */
function partition(hits: readonly Hit[]): { authored: Hit[]; bundled: Hit[] } {
  return {
    authored: hits.filter((h) => !h.minified),
    bundled: hits.filter((h) => h.minified),
  };
}

const evidenceFor = (hits: readonly Hit[]): Evidence[] =>
  hits.slice(0, 20).map((h) => ({ type: "file", path: h.path, line: h.line }));

const bullets = (hits: readonly Hit[]): string =>
  hits
    .slice(0, 20)
    .map((h) => `- \`${h.path}:${h.line}\` — ${h.what}`)
    .join("\n");

// ── 1. dynamic code execution ────────────────────────────────────────

type Lang =
  | "js"
  | "py"
  | "sh"
  | "go"
  | "rust"
  | "php"
  | "ruby"
  | "jvm"
  | "dotnet"
  | "swift"
  | "c"
  | "lua"
  | "perl"
  | "powershell";

/**
 * Which pattern set applies, or null for a language whose dangerous
 * shapes are not yet described.
 *
 * Returning null is not the same as "safe": the file is still read by
 * every language-agnostic check. It only means this particular check
 * has nothing precise to say, which is the honest position — a
 * half-guessed pattern for a language nobody here has tuned would
 * produce exactly the confident false positives this catalog keeps
 * having to walk back.
 */
function langOf(path: string): Lang | null {
  if (/\.m?[jt]sx?$/i.test(path)) return "js";
  if (/\.py$/i.test(path)) return "py";
  if (/\.(sh|bash|zsh)$/i.test(path)) return "sh";
  if (/\.go$/i.test(path)) return "go";
  if (/\.rs$/i.test(path)) return "rust";
  if (/\.php$/i.test(path)) return "php";
  if (/\.rb$/i.test(path)) return "ruby";
  // Java and Kotlin share a runtime and therefore share the shapes that
  // matter here — Runtime.exec, ProcessBuilder, ScriptEngine.
  if (/\.(java|kt|kts)$/i.test(path)) return "jvm";
  if (/\.(cs|fs|vb)$/i.test(path)) return "dotnet";
  if (/\.swift$/i.test(path)) return "swift";
  if (/\.(c|cc|cpp|h|hpp|m|mm)$/i.test(path)) return "c";
  if (/\.lua$/i.test(path)) return "lua";
  if (/\.(pl|pm)$/i.test(path)) return "perl";
  if (/\.ps1$/i.test(path)) return "powershell";
  return null;
}

/**
 * Patterns are scoped to a language, because the same word means
 * different things in each.
 *
 * Applying the Python rules to shell produced exactly the kind of
 * finding that discredits a checker: a published artifact was failed,
 * blocking, for the line
 *
 *     debug_log "using exec (container running)"
 *
 * which is an English log message. `exec` in shell is a builtin that
 * replaces the process image, `exec()` in Python compiles a string,
 * and `exec()` in Node runs a shell command — three unrelated things
 * that a single pattern list cannot tell apart.
 *
 * Within a language the distinguishing feature is the ARGUMENT.
 * `eval("2+2")` on a literal is pointless but harmless and stays
 * visible to review; `eval(decode(blob))` is a loader, and what runs is
 * not in the file. That second shape is what blocks, and it is the
 * mechanism the SFS-packing research measured bypassing every scanner
 * it tested.
 */

/** Does this file pull in the module that can run a shell command? */
const CHILD_PROCESS =
  /(?:require\s*\(\s*|from\s+|import\s+)["'](?:node:)?child_process["']|\bfrom\s+["']bun["']/;

/**
 * A method DECLARATION rather than a call.
 *
 * `public async exec(client: Requester)` defines a method named exec;
 * it runs nothing.
 */
const DECLARATION = /(^|\s)(function|async|public|private|protected|static|get|set)\s+[\w$]*\s*$/;

interface Pattern {
  re: RegExp;
  what: string;
  /** Only meaningful in a file that imports child_process. */
  needsChildProcess?: boolean;
}

const DYNAMIC_EXEC: Record<Lang, ReadonlyArray<Pattern>> = {
  js: [
    // Ordered before the generic eval rule: first match wins, and this
    // one is categorically worse. Evaluating a DECODED blob means the
    // payload is unreadable in the source at all, which is the shape
    // every dropper has. It must block even though plain
    // eval-on-a-variable is only a warning.
    {
      re: /\beval\s*\([^)]*(?:atob|Buffer\s*\.\s*from|fromCharCode|base64|unescape|decodeURI)/i,
      what: "eval of a constructed string",
    },
    { re: /\beval\s*\(\s*(?!["'`][^"'`]*["'`]\s*\))/, what: "eval() on a non-literal" },
    { re: /\bnew\s+Function\s*\(/, what: "new Function() — compiles a string into code" },
    {
      re: /\bvm\.(runInNewContext|runInThisContext|compileFunction)\s*\(/,
      what: "vm module execution",
    },
    // `exec` is not a reserved word. `regex.exec(s)` is in almost every
    // JavaScript file ever written, and `command.exec(client)` is an
    // ordinary method name — both were reported as shell execution
    // against a real published server until these were narrowed to a
    // bare call (never a member access) in a file that actually
    // imports child_process. See CHILD_PROCESS below.
    {
      re: /(?<![.\w$])(exec|execSync)\s*\(\s*(?!["'`])/,
      what: "child_process exec on a built string",
      needsChildProcess: true,
    },
    // The rule above skips anything starting with a quote, so that a
    // fully-literal command is left alone. That also let the classic
    // injection through: exec("ls " + dir) starts with a quote but is
    // assembled from a variable, and it is the exact shape this check
    // exists to catch. Matched separately rather than by loosening the
    // rule above, which would re-flag the literal commands it was
    // narrowed to permit.
    {
      re: /(?<![.\w$])(exec|execSync)\s*\(\s*["'`][^"'`]*["'`]\s*(?:\+|,\s*\w+\s*\+)/,
      what: "child_process exec on a built string",
      needsChildProcess: true,
    },
    // Template literals interpolate directly into the command string.
    {
      re: /(?<![.\w$])(exec|execSync)\s*\(\s*`[^`]*\$\{/,
      what: "child_process exec on a built string",
      needsChildProcess: true,
    },
    {
      re: /(?<![.\w$])(exec|execSync)\s*\(\s*["'`][^"'`]*\|\s*(ba)?sh\b/,
      what: "shell pipeline into sh",
      needsChildProcess: true,
    },
    {
      re: /(?<![.\w$])spawn(Sync)?\s*\(\s*["'`](ba)?sh["'`]\s*,\s*\[\s*["']-c["']/,
      what: "spawning `sh -c`",
      needsChildProcess: true,
    },
    { re: /\bimport\s*\(\s*(?!["'`])/, what: "dynamic import() of a computed specifier" },
  ],
  py: [
    { re: /\bos\.system\s*\(/, what: "os.system()" },
    {
      re: /\bsubprocess\.(call|run|check_output|Popen)\s*\([^)]*shell\s*=\s*True/,
      what: "subprocess with shell=True",
    },
    { re: /(?:^|[;=(,\s])exec\s*\(\s*(?!["'])/, what: "exec() on a built string" },
    { re: /(?:^|[;=(,\s])eval\s*\(\s*(?!["'][^"']*["']\s*\))/, what: "eval() on a non-literal" },
    { re: /(?<![.\w])compile\s*\([^)]*,\s*["']<?string>?["']/, what: "compile() of a string" },
  ],
  go: [
    // `exec.Command("sh", "-c", …)` is Go's shell-out. GitHub's own MCP
    // server is Go, and so is a growing share of the ecosystem.
    {
      re: /\bexec\.Command(?:Context)?\s*\(\s*(?:[a-zA-Z_][\w.]*\s*,\s*)?["`](?:\/bin\/)?(?:ba|z)?sh["`]\s*,/,
      what: "spawning a shell via exec.Command",
    },
    // NOT flagged: `exec.Command(name, args...)` with a computed name.
    // Go's exec.Command does not invoke a shell — it execs a binary
    // directly, which makes it the equivalent of Node's `spawn` with an
    // argv array, the form this check ASKS people to use. Flagging it
    // failed github/github-mcp-server on
    // `exec.Command(cmdParts[0], cmdParts[1:]...)`, which is the safe
    // idiom. The shell only enters via an explicit "sh" -c.
    { re: /\b(?:curl|wget)\b[^"`]*\|\s*(?:ba|z)?sh\b/, what: "piping a download into a shell" },
  ],
  rust: [
    {
      re: /\bCommand::new\s*\(\s*"(?:\/bin\/)?(?:ba|z)?sh"\s*\)/,
      what: "spawning a shell via Command::new",
    },
    // Same reasoning as Go: Rust's Command::new execs a binary, it
    // does not go through a shell.
  ],
  php: [
    { re: /\b(?:eval|assert)\s*\(\s*(?!["'])/, what: "eval() on a built string" },
    {
      re: /\b(?:shell_exec|passthru|system|popen|proc_open)\s*\(/,
      what: "shell execution",
    },
    { re: /\bbase64_decode\s*\([^)]*\)\s*\)?\s*;?\s*$/m, what: "decoding a payload" },
  ],
  // Same argv rule as Go and Rust throughout the block below: a call
  // that takes a program plus an argument LIST does not involve a
  // shell, and flagging it would condemn the exact form these checks
  // ask people to use. Only an explicit shell, or a string handed to an
  // interpreter, is dangerous.
  jvm: [
    {
      re: /\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(\s*(?!new\s+String\s*\[)/,
      what: "shell execution on a built string",
    },
    {
      re: /\bProcessBuilder\s*\(\s*["'](?:\/bin\/)?(?:ba|z)?sh["']\s*,\s*["']-c["']/,
      what: "spawning `sh -c`",
    },
    { re: /\bScriptEngine\w*\s*\.\s*eval\s*\(/, what: "eval() on a non-literal" },
    { re: /\bGroovyShell\s*\(\s*\)\s*\.\s*evaluate\s*\(/, what: "eval of a constructed string" },
  ],
  dotnet: [
    {
      re: /\bProcess\s*\.\s*Start\s*\(\s*["'](?:cmd(?:\.exe)?|powershell(?:\.exe)?|\/bin\/(?:ba)?sh)["']\s*,/i,
      what: "shell execution",
    },
    {
      re: /\bFileName\s*=\s*["'](?:cmd(?:\.exe)?|powershell(?:\.exe)?)["']/i,
      what: "shell execution",
    },
    { re: /\bCSharpScript\s*\.\s*(?:Evaluate|Run)\w*\s*\(/, what: "eval of a constructed string" },
  ],
  swift: [
    { re: /\blaunchPath\s*=\s*["']\/bin\/(?:ba|z)?sh["']/, what: "spawning `sh -c`" },
    {
      re: /\bexecutableURL\s*=\s*URL\([^)]*["']\/bin\/(?:ba|z)?sh["']/,
      what: "spawning `sh -c`",
    },
    { re: /(?<![.\w])system\s*\(\s*(?!["'])/, what: "shell execution on a built string" },
  ],
  c: [
    // system() and popen() hand their argument to /bin/sh, so a
    // constructed string is a shell injection by construction. A string
    // literal is left alone — it is visible to review.
    { re: /(?<![.\w>])system\s*\(\s*(?!["'])/, what: "shell execution on a built string" },
    { re: /(?<![.\w>])popen\s*\(\s*(?!["'])/, what: "shell execution on a built string" },
    { re: /\bexecl?p?\s*\(\s*["'](?:\/bin\/)?(?:ba|z)?sh["']\s*,/, what: "spawning `sh -c`" },
  ],
  lua: [
    { re: /\bos\s*\.\s*execute\s*\(\s*(?!["'])/, what: "shell execution on a built string" },
    { re: /\bio\s*\.\s*popen\s*\(\s*(?!["'])/, what: "shell execution on a built string" },
    { re: /\b(?:loadstring|load)\s*\(\s*(?!["'])/, what: "eval() on a non-literal" },
  ],
  perl: [
    { re: /(?<![.\w])system\s*\(\s*(?!["'])/, what: "shell execution on a built string" },
    { re: /`[^`]*\$\{?\w/, what: "backtick execution with interpolation" },
    { re: /\bopen\s*\([^,]+,\s*["'][^"']*\|\s*["']/, what: "shell execution" },
    { re: /(?<![.\w])eval\s*(?:\{|\(\s*["']?\$)/, what: "eval() on a non-literal" },
  ],
  powershell: [
    // Invoke-Expression is PowerShell's eval, and `iex` is its alias —
    // the download-and-run one-liner every dropper on Windows uses.
    // Ordered before the bare form: first match wins, and a download
    // piped into iex is the more specific and more serious finding.
    {
      re: /\b(?:Invoke-WebRequest|iwr|curl|wget)\b[^\n|]*\|\s*(?:Invoke-Expression|iex)\b/i,
      what: "piping a download into a shell",
    },
    // Labelled as shell execution, NOT as in-process eval. PowerShell's
    // Invoke-Expression runs arbitrary COMMANDS, so it belongs with
    // `sh -c` rather than with `new Function` — mislabelling it put the
    // canonical Windows dropper one-liner in the warn bucket.
    { re: /\b(?:Invoke-Expression|iex)\b/i, what: "shell execution" },
    { re: /\bStart-Process\s+["']?(?:cmd|powershell)/i, what: "shell execution" },
  ],
  ruby: [
    { re: /\beval\s*\(\s*(?!["'])/, what: "eval() on a built string" },
    { re: /\b(?:system|exec)\s*\(\s*(?!["'])/, what: "shell execution on a built string" },
    { re: /`[^`]*\$\{/, what: "backtick execution with interpolation" },
  ],
  sh: [
    // The actual shell-side attack: fetch a script and run it unseen.
    {
      re: /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|d)?sh\b/,
      what: "piping a downloaded script straight into a shell",
    },
    { re: /\b(ba|z)?sh\s+<\(\s*(curl|wget)\b/, what: "process substitution running a download" },
    { re: /\beval\s+["'$]/, what: "eval of a constructed string" },
  ],
};

/**
 * Whether a position sits inside a quoted string.
 *
 * A pattern inside a string literal is data — a log message, a usage
 * line, an error the program prints. Matching it reports the artifact
 * for describing a thing rather than doing it.
 */
function inStringLiteral(line: string, index: number): boolean {
  let single = false;
  let double = false;
  let backtick = false;
  for (let i = 0; i < index; i++) {
    const c = line[i];
    if (c === "\\") {
      i++;
      continue;
    }
    if (c === "'" && !double && !backtick) single = !single;
    else if (c === '"' && !single && !backtick) double = !double;
    else if (c === "`" && !single && !double) backtick = !backtick;
  }
  return single || double || backtick;
}

/**
 * Findings severe enough to justify removing an artifact from a public
 * registry, as opposed to flagging it.
 *
 * The distinction this draws is between "what runs is not what is
 * written" and "a shell or an opaque payload is involved".
 *
 * Running the check across 50 published artifacts made the case: seven
 * were blocked on `no-dynamic-code-execution`, and the ones I read were
 * genuine findings about legitimate code — lastmile-ai/mcp-agent builds
 * pydantic models with `exec(func_code, namespace)` in a type
 * serializer. That is real dynamic execution and worth surfacing, but
 * delisting a widely-used framework for a codegen idiom is a false
 * accusation dressed as a safety verdict, and it would have taught
 * publishers that the score is noise.
 *
 * What stays blocking is the set where an installer is plausibly
 * harmed: a shell (which turns a string into arbitrary commands), a
 * download piped into one, or code recovered from an encoded blob
 * (where the payload is deliberately unreadable). Everything else is a
 * warning that still costs score and still names the file and line.
 */
const BLOCKING_WHAT = new Set([
  // A shell turns a constructed string into arbitrary commands.
  "shell execution",
  "shell execution on a built string",
  "shell pipeline into sh",
  "spawning `sh -c`",
  "spawning a shell via Command::new",
  "spawning a shell via exec.Command",
  "subprocess with shell=True",
  "os.system()",
  "backtick execution with interpolation",
  "child_process exec on a built string",
  // Remote code fetched and executed in one step.
  "piping a download into a shell",
  "piping a downloaded script straight into a shell",
  "process substitution running a download",
  // The payload is encoded, so the source cannot be reviewed at all.
  "decoding a payload",
  "eval of a constructed string",
]);

/**
 * Files under `scripts/` that no lifecycle hook runs.
 *
 * A demo recorder and a dependency updater are developer tooling: the
 * publisher runs them, an installer never does. Blocking an artifact
 * because its release script shells out punishes maintenance work that
 * is not part of what anyone installs, and in a 50-artifact sample it
 * was the single largest category of blocked artifacts.
 *
 * Deliberately NOT a blanket exemption for `scripts/`. npm lifecycle
 * hooks live exactly there, and `postinstall` is one of the most direct
 * ways to attack whoever installs a package — excluding the directory
 * wholesale would open a real hole to remove a cosmetic annoyance. So
 * anything package.json actually references stays fully in scope, and
 * only the unreferenced remainder is downgraded. Downgraded, not
 * hidden: these findings are still reported and still cost score.
 */
async function unreferencedDevScripts(ctx: CheckContext): Promise<(p: string) => boolean> {
  const raw = await ctx.source.readFile("package.json");
  if (!raw) {
    // No package.json means no lifecycle hooks to respect, but also no
    // evidence either way. Treating everything as referenced is the
    // conservative reading and keeps the old behaviour.
    return () => false;
  }
  let referenced = "";
  try {
    const pkg = JSON.parse(raw) as { scripts?: Record<string, string> };
    referenced = Object.values(pkg.scripts ?? {}).join("\n");
  } catch {
    return () => false;
  }
  return (path) => {
    if (!/(^|\/)scripts\//.test(path)) return false;
    // Substring match on the whole scripts block: a hook invoking
    // `node scripts/build.mjs` mentions the path verbatim, and matching
    // loosely errs toward keeping a file in scope rather than out.
    const leaf = path.split("/").pop() ?? path;
    return !referenced.includes(path) && !referenced.includes(leaf);
  };
}

export const noDynamicCodeExecution = defineCheck({
  id: "no-dynamic-code-execution",
  version: "1.0.0",
  title: "No code built at runtime",
  category: "safety",
  axis: "safety",
  determinism: "deterministic",
  weight: 5,
  blocking: true,
  spec: checkSpecUrl("no-dynamic-code-execution"),
  inspects: "Source files, for constructs that turn data into executable code.",
  rationale:
    "An artifact that assembles its own code at runtime cannot be reviewed by reading it — what executes is not in the file. This is the mechanism behind self-extracting packing, which bypassed every one of nine scanners tested at 90% or better. A literal argument is exempt because it stays visible; a computed one is not.",
  examples: {
    passing: "const cfg = JSON.parse(raw);",
    failing: 'eval(Buffer.from(blob, "base64").toString());',
  },
  async run(ctx): Promise<CheckResult> {
    /** Whether each file imports child_process, computed once per file. */
    const importsChildProcess = new Map<string, boolean>();

    const { hits, scanned } = await scan(ctx, (line, path, all) => {
      // A commented-out line is documentation, not execution.
      if (/^\s*(\/\/|#|\*)/.test(line)) return null;
      const lang = langOf(path);
      if (!lang) return null;

      if (!importsChildProcess.has(path)) {
        importsChildProcess.set(
          path,
          all.some((l) => CHILD_PROCESS.test(l)),
        );
      }

      for (const p of DYNAMIC_EXEC[lang]) {
        if (p.needsChildProcess && !importsChildProcess.get(path)) continue;
        const m = p.re.exec(line);
        if (!m) continue;
        // Shell command substitution runs inside double quotes, so the
        // string-literal exemption would hide real findings there.
        if (lang !== "sh" && inStringLiteral(line, m.index)) continue;
        if (DECLARATION.test(line.slice(0, m.index))) continue;
        return p.what;
      }
      return null;
    });

    if (scanned === 0) return { status: "neutral", summary: "No source files to read." };
    if (hits.length === 0) {
      return { status: "pass", summary: `No runtime code construction in ${scanned} files.` };
    }
    const { authored, bundled } = partition(hits);
    if (authored.length === 0) {
      return {
        status: "warn",
        summary: `${bundled.length} runtime-code construct${bundled.length === 1 ? "" : "s"} inside bundled files.`,
        detail:
          `${bullets(bundled)}\n\n` +
          "These are in minified bundles, so they are most likely inlined dependency code rather than something the publisher wrote. Reported, not blocked.",
        remediation:
          "If the bundle is generated, no action is needed. Publishing unminified source alongside it makes this reviewable.",
        evidence: evidenceFor(bundled),
      };
    }
    // Split by severity. A shell or an encoded payload blocks; building
    // code at runtime in-process is reported and scored, not delisted.
    // Dev tooling no lifecycle hook runs is reported but does not block.
    const isDevOnly = await unreferencedDevScripts(ctx);
    const severe = authored.filter((h) => BLOCKING_WHAT.has(h.what) && !isDevOnly(h.path));
    const remediation =
      "Replace dynamic execution with an explicit dispatch table or a parsed data format. If a shell command is genuinely required, pass an argument array rather than a string, and never interpolate untrusted input into it.";

    if (severe.length === 0) {
      return {
        status: "warn",
        summary: `${authored.length} construct${authored.length === 1 ? " that builds" : "s that build"} code at runtime.`,
        detail:
          `${bullets(authored)}\n\n` +
          "What runs is not what is written here, so reviewing the source does not tell you what the artifact does. No shell and no encoded payload is involved, so this is reported rather than blocked — it is a review burden, not a demonstrated danger.",
        remediation,
        evidence: evidenceFor(authored),
      };
    }

    return {
      status: "fail",
      summary: `${severe.length} construct${severe.length === 1 ? "" : "s"} that can run arbitrary commands.`,
      detail:
        `${bullets(severe)}\n\n` +
        "A shell or an encoded payload is involved, so what executes is both unreadable here and unbounded at runtime." +
        (authored.length > severe.length
          ? ` ${authored.length - severe.length} further runtime-code construct${authored.length - severe.length === 1 ? " was" : "s were"} found but did not involve a shell.`
          : ""),
      remediation,
      evidence: evidenceFor(severe),
    };
  },
});

// ── 2. obfuscated payloads ───────────────────────────────────────────

/** A base64 run long enough to hide something meaningful. */
const B64 = /["'`]([A-Za-z0-9+/]{40,}={0,2})["'`]/g;
/** A long hex run — the other common encoding. */
const HEX = /["'`]((?:[0-9a-fA-F]{2}){24,})["'`]/g;

/** Shapes that mean the decoded bytes are instructions, not data. */
const DECODED_IS_CODE =
  /\b(curl|wget|chmod|bash|\/bin\/sh|rm\s+-rf|nc\s|base64\s+-d|eval|require\(|import\s|process\.env|child_process|os\.system|subprocess)\b|^#!/;

function decodeB64(s: string): string | null {
  try {
    const out = Buffer.from(s, "base64").toString("utf8");
    // Reject binary: if most of it is unprintable it is an asset, not
    // a script, and assets are a perfectly ordinary thing to embed.
    const printable = out.replace(/[^\x20-\x7e\n\r\t]/g, "").length;
    return printable / Math.max(1, out.length) > 0.85 ? out : null;
  } catch {
    return null;
  }
}

function decodeHex(s: string): string | null {
  try {
    const out = Buffer.from(s, "hex").toString("utf8");
    const printable = out.replace(/[^\x20-\x7e\n\r\t]/g, "").length;
    return printable / Math.max(1, out.length) > 0.85 ? out : null;
  } catch {
    return null;
  }
}

export const noObfuscatedPayloads = defineCheck({
  id: "no-obfuscated-payloads",
  version: "1.0.0",
  title: "No encoded executable payloads",
  category: "safety",
  axis: "safety",
  determinism: "deterministic",
  weight: 5,
  blocking: true,
  spec: checkSpecUrl("no-obfuscated-payloads"),
  inspects: "Long base64 and hex string literals, decoded and inspected.",
  rationale:
    "Encoding is not itself suspicious — images, certificates and test vectors are legitimately embedded. What matters is what the bytes DECODE to. This check decodes them and only reports when the result reads as shell or code, which is a shape with no innocent explanation.",
  examples: {
    passing: 'const LOGO = "iVBORw0KGgoAAAANS…";  // a PNG',
    failing: 'const b = "Y3VybCAtcyBodHRwOi8v…";  // decodes to `curl -s http://…`',
  },
  async run(ctx): Promise<CheckResult> {
    const { hits, scanned } = await scan(ctx, (line) => {
      for (const [re, dec, label] of [
        [B64, decodeB64, "base64"],
        [HEX, decodeHex, "hex"],
      ] as const) {
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = re.exec(line)) !== null) {
          const decoded = dec(m[1]!);
          if (decoded && DECODED_IS_CODE.test(decoded)) {
            // Name the shape, never the payload — printing it would
            // republish the thing we are warning about.
            const kind = /^#!|\b(curl|wget|bash|\/bin\/sh|chmod)\b/.test(decoded)
              ? "a shell command"
              : "executable code";
            return `${label} literal decoding to ${kind}`;
          }
        }
      }
      return null;
    });

    if (scanned === 0) return { status: "neutral", summary: "No source files to read." };
    if (hits.length === 0) {
      return { status: "pass", summary: `No encoded payloads in ${scanned} files.` };
    }
    const { authored, bundled } = partition(hits);
    const relevant = authored.length > 0 ? authored : bundled;
    const n = relevant.length;
    return {
      status: authored.length > 0 ? "fail" : "warn",
      summary: `${n} encoded payload${n === 1 ? "" : "s"} ${n === 1 ? "that decodes" : "that decode"} to executable content${authored.length > 0 ? "" : ", inside bundled files"}.`,
      detail:
        `${bullets(relevant)}\n\n` +
        "The decoded content is deliberately not reproduced here. Encoding hides intent from review while changing nothing about what runs." +
        (authored.length > 0
          ? ""
          : "\n\nThese are in minified bundles, so they are most likely inlined dependency code. Reported, not blocked."),
      remediation:
        "Ship the code as source. If the data genuinely needs encoding, keep it inert — do not pass it to an interpreter, a shell, or a file that is later executed.",
      evidence: evidenceFor(relevant),
    };
  },
});

// ── 3. undeclared network egress ─────────────────────────────────────

/** A raw IPv4 literal — almost never a legitimate hardcoded endpoint. */
const RAW_IP =
  /\bhttps?:\/\/(?!127\.0\.0\.1|0\.0\.0\.0|localhost)((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?/;
/** An http(s) host in code. */
const URL_RE = /\bhttps?:\/\/([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?:[/:?#]|\b)/g;
/** A hardcoded recipient. The postmark backdoor was exactly one line of this. */
const EMAIL_SINK =
  /\b(bcc|cc|to|recipient|forward|notify|report_to|webhook)\b\s*[:=]\s*["'`]([^"'`@\s]+@[^"'`\s]+)["'`]/i;

/**
 * Hosts that are infrastructure rather than destinations.
 *
 * Reaching a package registry or a docs site is what artifacts do; the
 * signal is a destination the documentation never mentions.
 */
const INFRA =
  /(^|\.)(npmjs\.(org|com)|pypi\.org|files\.pythonhosted\.org|github\.com|githubusercontent\.com|gitlab\.com|crates\.io|golang\.org|rubygems\.org|maven\.org|docker\.io|schemastore\.org|json-schema\.org|w3\.org|apache\.org|mozilla\.org|python\.org|nodejs\.org|modelcontextprotocol\.io|anthropic\.com|openai\.com|localhost)$/i;

export const noUndeclaredEgress = defineCheck({
  id: "no-undeclared-egress",
  version: "1.0.0",
  title: "No undocumented network destinations",
  category: "safety",
  axis: "safety",
  determinism: "deterministic",
  weight: 4,
  blocking: true,
  spec: checkSpecUrl("no-undeclared-egress"),
  inspects:
    "Hardcoded hosts, raw IP addresses and message recipients in source, compared against the documentation.",
  rationale:
    "An artifact that sends data somewhere its documentation never mentions is the shape of every exfiltration backdoor, and the postmark-mcp compromise was literally one line adding a hardcoded BCC. A raw IP address blocks outright: there is no legitimate reason to hardcode one, and it is how a payload reaches a host with no domain to revoke.",
  examples: {
    passing: "const API = process.env.SERVICE_URL;",
    failing: 'msg.bcc = "harvest@attacker-domain.tld";',
  },
  async run(ctx): Promise<CheckResult> {
    // Everything the documentation openly mentions is declared, and a
    // declared destination is not a hidden one.
    const tree = await ctx.source.listTree();
    let docs = "";
    for (const e of tree) {
      if (e.type === "file" && /\.(md|txt)$/i.test(e.path) && !SKIP.test(e.path)) {
        docs += (await ctx.source.readFile(e.path)) ?? "";
      }
    }
    const declared = new Set<string>();
    let dm: RegExpExecArray | null;
    URL_RE.lastIndex = 0;
    while ((dm = URL_RE.exec(docs)) !== null) declared.add(dm[1]!.toLowerCase());
    for (const m of docs.matchAll(/[\w.+-]+@[\w.-]+\.\w+/g)) declared.add(m[0].toLowerCase());

    const { hits, scanned } = await scan(ctx, (line) => {
      if (/^\s*(\/\/|#|\*)/.test(line)) return null;

      const ip = RAW_IP.exec(line);
      if (ip) return `hardcoded IP address ${ip[1]}`;

      const sink = EMAIL_SINK.exec(line);
      if (sink && !declared.has(sink[2]!.toLowerCase())) {
        return `message ${sink[1]!.toLowerCase()} hardcoded to an address the documentation never mentions`;
      }

      URL_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = URL_RE.exec(line)) !== null) {
        const host = m[1]!.toLowerCase();
        if (INFRA.test(host) || declared.has(host)) continue;
        return `undocumented host ${host}`;
      }
      return null;
    });

    if (scanned === 0) return { status: "neutral", summary: "No source files to read." };
    if (hits.length === 0) {
      return { status: "pass", summary: `No undocumented destinations in ${scanned} files.` };
    }

    // A raw IP or a hidden recipient has no innocent reading. An
    // undocumented hostname often does — a status page, a CDN the
    // author forgot to mention — so that warns instead.
    const { authored } = partition(hits);
    const severe = authored.filter((h) => /IP address|hardcoded to an address/.test(h.what));
    const blocking = severe.length > 0;
    const relevant = blocking ? severe : hits;

    return {
      status: blocking ? "fail" : "warn",
      summary: blocking
        ? `${severe.length} hardcoded exfiltration destination${severe.length === 1 ? "" : "s"}.`
        : `${hits.length} network destination${hits.length === 1 ? "" : "s"} the documentation does not mention.`,
      detail:
        `${bullets(relevant)}\n\n` +
        (blocking
          ? "A raw IP or a recipient baked into the source is where data goes, decided by the author rather than the user, and invisible unless you read every line."
          : "These may be legitimate. The point is that a reader of the documentation would not know the artifact talks to them."),
      remediation: blocking
        ? "Remove the hardcoded destination. Take endpoints from configuration or the environment so the operator decides where data goes."
        : "Document these destinations, or move them into configuration.",
      evidence: evidenceFor(relevant),
    };
  },
});

// ── 4. typosquatted dependencies ─────────────────────────────────────

/**
 * Popular packages, and the neighbourhood an attacker aims at.
 *
 * Deliberately a short, high-traffic list rather than a scrape. The
 * check answers one question — "is this one keystroke away from
 * something far more popular?" — and a longer list buys more false
 * positives than signal.
 */
const POPULAR = [
  "requests",
  "lodash",
  "express",
  "react",
  "axios",
  "chalk",
  "commander",
  "colors",
  "debug",
  "moment",
  "dotenv",
  "typescript",
  "webpack",
  "babel",
  "eslint",
  "jest",
  "mocha",
  "vue",
  "angular",
  "jquery",
  "bluebird",
  "numpy",
  "pandas",
  "flask",
  "django",
  "urllib3",
  "pillow",
  "scipy",
  "setuptools",
  "cryptography",
  "beautifulsoup4",
  "pyyaml",
  "six",
  "openai",
  "anthropic",
  "fastapi",
  "pydantic",
  "sqlalchemy",
  "boto3",
];

/** Levenshtein, bounded — we only care about distance 1 or 2. */
function editDistance(a: string, b: string, max = 2): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let best = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + cost);
      best = Math.min(best, cur[j]!);
    }
    if (best > max) return max + 1;
    prev = cur;
  }
  return prev[b.length]!;
}

export const depsNotTyposquatted = defineCheck({
  id: "deps-not-typosquatted",
  version: "1.1.0",
  title: "No dependencies that impersonate popular packages",
  category: "supply-chain",
  axis: "safety",
  determinism: "deterministic",
  weight: 4,
  blocking: true,
  spec: checkSpecUrl("deps-not-typosquatted"),
  inspects: "Declared dependency names, against a list of high-traffic packages.",
  rationale:
    "Typosquatting is the cheapest supply-chain attack there is: register a name one keystroke from something popular and wait. A dependency named `reqeusts` or `lodahs` is not a typo the author made once — it is a package that exists because someone registered it.",
  examples: {
    passing: '"dependencies": { "lodash": "^4.17.21" }',
    failing: '"dependencies": { "lodahs": "^4.0.0" }',
  },
  async run(ctx): Promise<CheckResult> {
    const raw = await ctx.source.readFile("package.json");
    const py =
      (await ctx.source.readFile("requirements.txt")) ??
      (await ctx.source.readFile("pyproject.toml"));
    if (!raw && !py) {
      return { status: "neutral", summary: "No dependency manifest to read." };
    }

    const names: string[] = [];
    if (raw) {
      try {
        const pkg = JSON.parse(raw) as Record<string, Record<string, string> | undefined>;
        for (const field of ["dependencies", "optionalDependencies", "peerDependencies"]) {
          names.push(...Object.keys(pkg[field] ?? {}));
        }
      } catch {
        /* an unparseable manifest is `manifest-present`'s finding, not ours */
      }
    }
    if (py) {
      for (const m of py.matchAll(/^\s*["']?([A-Za-z][A-Za-z0-9._-]{2,})["']?\s*(?:[=<>~!]|$)/gm)) {
        names.push(m[1]!);
      }
    }
    if (names.length === 0) {
      return { status: "neutral", summary: "No dependencies declared." };
    }

    const hits: { name: string; looksLike: string; distance: number }[] = [];
    for (const full of names) {
      // Scoped packages are namespaced by their owner, so `@acme/react`
      // is not impersonating `react`.
      if (full.startsWith("@")) continue;
      const name = full.toLowerCase();
      for (const p of POPULAR) {
        if (name === p) break;
        const d = editDistance(name, p);
        // Length difference is the discriminator, not edit distance
        // alone. A typosquat is a name meant to be MISREAD as another:
        // a transposition (`lodahs`/`lodash`) or a substitution, which
        // leave the length alone or move it by one. Allowing two
        // flagged `cors` — the Express middleware, ~10M downloads a
        // week — as a squat of `colors`, which is two insertions into a
        // four-letter word, and would have blocked the official MCP
        // reference server.
        if (d <= 2 && Math.abs(name.length - p.length) <= 1 && name.length >= 4) {
          hits.push({ name: full, looksLike: p, distance: d });
          break;
        }
      }
    }

    if (hits.length === 0) {
      return {
        status: "pass",
        summary: `${names.length} dependencies, none impersonating a popular package.`,
      };
    }
    return {
      status: "fail",
      summary: `${hits.length} dependenc${hits.length === 1 ? "y" : "ies"} named like a more popular package.`,
      detail:
        hits
          .map(
            (h) =>
              `- \`${h.name}\` is ${h.distance} character${h.distance === 1 ? "" : "s"} from \`${h.looksLike}\``,
          )
          .join("\n") + "\n\nA name this close to a high-traffic package is registered on purpose.",
      remediation:
        "Check whether you meant the popular package. If the dependency is genuinely what you want, waive this check with the reason — the waiver is published in the report.",
      evidence: [{ type: "file", path: raw ? "package.json" : "requirements.txt" }],
    };
  },
});

// ── 5. credentials assembled from parts ─────────────────────────────

/**
 * Credential shapes, matched after folding.
 *
 * Only prefixes with a fixed, issuer-assigned form — the ones where a
 * match is the credential rather than a guess.
 */
const SECRET_SHAPES: ReadonlyArray<{ re: RegExp; what: string }> = [
  { re: /\bAKIA[0-9A-Z]{16}\b/, what: "an AWS access key id" },
  { re: /\bASIA[0-9A-Z]{16}\b/, what: "an AWS temporary access key id" },
  { re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/, what: "a GitHub token" },
  { re: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/, what: "a GitHub fine-grained token" },
  { re: /\bsk-(ant-)?[A-Za-z0-9_-]{32,}\b/, what: "a model-provider API key" },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/, what: "a Slack token" },
  { re: /\bAIza[0-9A-Za-z_-]{35}\b/, what: "a Google API key" },
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/, what: "a private key" },
];

/**
 * Fold the string arithmetic a human would do by eye.
 *
 * Not an evaluator — it resolves single-literal constants, joins `+`
 * chains, expands `.repeat(n)` and collapses `[…].join("")`. That is
 * the entire vocabulary of splitting a token across a file, and it is
 * enough because the attacker's constraint is that the pieces must
 * reassemble into an exact string at runtime.
 */
function foldStrings(body: string): string {
  const consts = new Map<string, string>();
  // Deliberately does NOT require a `const`/`let`/`var` keyword: the
  // second binding in `const A = "…", B = "…"` has no keyword of its
  // own, and that is exactly where a split token hides.
  const declRe =
    /(?:^|[;,{(\s])([A-Za-z_$][\w$]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')\s*(?=[;,)\]\n])/gm;
  let d: RegExpExecArray | null;
  while ((d = declRe.exec(body)) !== null) {
    consts.set(d[1]!, d[2] ?? d[3] ?? "");
  }

  let out = body;

  // "x".repeat(36) → "xxx…"
  out = out.replace(/(?:"([^"]*)"|'([^']*)')\s*\.repeat\(\s*(\d{1,4})\s*\)/g, (_m, a, b, n) => {
    const s = (a ?? b ?? "") as string;
    const count = Math.min(Number(n), 512);
    return JSON.stringify(s.repeat(count));
  });

  // ["a","b"].join("") → "ab"
  //
  // The element list is written string-first, comma-separated, with an
  // optional trailing comma — NOT `(?:\s*STR\s*,?)+`. That shape put
  // `\s*` on both sides of an optional comma inside a `+`, which gave
  // the engine exponentially many ways to split the whitespace whenever
  // the overall match went on to fail — and in a Python file every long
  // string list fails it, because Python spells this `"".join(list)`.
  // One 79 KB .py file held the checker at 100% CPU for 40+ minutes.
  out = out.replace(
    /\[\s*((?:"[^"]*"|'[^']*')(?:\s*,\s*(?:"[^"]*"|'[^']*'))*)\s*,?\s*\]\s*\.join\(\s*(?:""|'')\s*\)/g,
    (_m, inner) => {
      const parts = String(inner).match(/"([^"]*)"|'([^']*)'/g) ?? [];
      return JSON.stringify(parts.map((p) => p.slice(1, -1)).join(""));
    },
  );

  // Substitute known constants where they appear in a `+` chain, then
  // fold literal + literal until nothing changes.
  out = out.replace(
    /\b([A-Za-z_$][\w$]*)\b(?=\s*\+)|(?<=\+\s*)\b([A-Za-z_$][\w$]*)\b/g,
    (m, a, b) => {
      const name = (a ?? b) as string;
      const v = consts.get(name);
      return v === undefined ? m : JSON.stringify(v);
    },
  );

  for (let i = 0; i < 12; i++) {
    const next = out.replace(
      /(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')\s*\+\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')/g,
      (_m, a, b, c, e) => JSON.stringify((a ?? b ?? "") + (c ?? e ?? "")),
    );
    if (next === out) break;
    out = next;
  }
  return out;
}

export const noAssembledCredentials = defineCheck({
  id: "no-assembled-credentials",
  // 1.0.1: the join-folding regex was rewritten to an unambiguous
  // grammar after catastrophic backtracking on long non-joined string
  // lists (idiomatic Python) pinned the checker at 100% CPU. Verdicts
  // on well-formed inputs are unchanged; inputs that previously never
  // returned now do.
  version: "1.0.1",
  title: "No credentials assembled from parts",
  category: "safety",
  axis: "safety",
  determinism: "deterministic",
  weight: 5,
  blocking: true,
  spec: checkSpecUrl("no-assembled-credentials"),
  inspects:
    "Source files, with string concatenation folded before credential patterns are applied.",
  rationale:
    "Scanning for credentials line by line is defeated by splitting one across two variables — a technique that takes ten seconds and beats every grep-based scanner. Folding the concatenation first restores what the runtime will actually see, so the evasion buys nothing.",
  examples: {
    passing: "const KEY = process.env.AWS_ACCESS_KEY_ID;",
    failing: 'const A = "AKIA", B = "IOSFODNN7EXAMPLE";\nconst KEY = A + B;',
  },
  async run(ctx): Promise<CheckResult> {
    const hits: Hit[] = [];
    const scanned = await eachFile(ctx, (path, body, minified) => {
      // Folding a minified bundle is meaningless — it is one line, and
      // its string tables are somebody else's.
      if (minified) return;
      const folded = foldStrings(body);
      if (folded === body) return; // nothing was assembled

      const raw = body.split("\n");
      const foldedLines = folded.split("\n");
      for (let i = 0; i < foldedLines.length; i++) {
        const line = foldedLines[i]!;
        for (const s of SECRET_SHAPES) {
          // Only report what folding REVEALED. A secret sitting in
          // plain sight is `no-hardcoded-credentials`' finding, and
          // reporting it twice makes the report look padded.
          const m = s.re.exec(line);
          if (m && !s.re.test(raw[i] ?? "") && !isPlaceholder(m[0])) {
            hits.push({ path, line: i + 1, what: `${s.what}, split across parts` });
            break;
          }
        }
      }
    });

    if (scanned === 0) return { status: "neutral", summary: "No source files to read." };
    if (hits.length === 0) {
      return { status: "pass", summary: `No assembled credentials in ${scanned} files.` };
    }
    return {
      status: "fail",
      summary: `${hits.length} credential${hits.length === 1 ? "" : "s"} assembled from parts at runtime.`,
      detail:
        `${bullets(hits)}\n\n` +
        "Each is split across literals so that no single line matches a credential pattern. The value at runtime is the credential.",
      remediation:
        "Read credentials from the environment or a secret store. If these are test vectors, move them under a `tests/` or `fixtures/` directory, which this check does not scan.",
      evidence: evidenceFor(hits),
    };
  },
});

export const CODE_CHECKS = [
  noDynamicCodeExecution,
  noObfuscatedPayloads,
  noUndeclaredEgress,
  depsNotTyposquatted,
  noAssembledCredentials,
];
