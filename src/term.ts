/**
 * Terminal primitives: colour, symbols, layout, progress.
 *
 * Written rather than imported, and that is a deliberate trade. The
 * usual stack for this — chalk, ora, cli-progress, prompts — is four
 * dependencies and a few dozen transitive packages, in a tool whose own
 * checks warn you about unbounded dependency ranges and install-time
 * scripts. Shipping that to make text blue would be hard to defend to
 * anyone reading our own output. None of what follows is difficult; it
 * is ~200 lines of ANSI and a few `\r` writes.
 *
 * Everything degrades. Colour disappears under NO_COLOR, when stdout is
 * not a TTY, and in CI. Spinners never render to a pipe — a progress
 * animation in a log file is line noise, and a report that cannot be
 * piped through `jq` is a report nobody automates.
 */

const ESC = "[";

/**
 * Should we emit colour?
 *
 * Precedence follows the informal standard the ecosystem settled on:
 * NO_COLOR wins over everything (https://no-color.org), FORCE_COLOR
 * overrides detection for people piping into something that renders
 * ANSI, and otherwise we colour only a real terminal.
 */
export function colorEnabled(env: NodeJS.ProcessEnv = process.env, isTty = process.stdout.isTTY) {
  if (env["NO_COLOR"] !== undefined && env["NO_COLOR"] !== "") return false;
  if (env["FORCE_COLOR"] !== undefined && env["FORCE_COLOR"] !== "0") return true;
  if (env["TERM"] === "dumb") return false;
  return Boolean(isTty);
}

/**
 * Should animated progress render at all?
 *
 * Beyond the TTY and CI checks, this is an accessibility control. `gh`
 * documents the reason better than we could: interactive UIs "manipulate
 * the terminal cursor to redraw parts of the screen, which can be
 * difficult for speech synthesizers or braille displays to accurately
 * detect", and motion "may cause discomfort to users with motion
 * sensitivity". One environment variable is a very cheap fix for that.
 */
export function spinnerEnabled(
  env: NodeJS.ProcessEnv = process.env,
  isTty = process.stderr.isTTY,
): boolean {
  if (env["ASSAY_NO_SPINNER"] !== undefined && env["ASSAY_NO_SPINNER"] !== "") return false;
  // Generic CI detection: any non-empty value, since runners variously
  // set `1`, `true`, and `True`.
  if (env["CI"]) return false;
  return Boolean(isTty);
}

/** Unicode is not universal — Windows consoles and some CI logs mangle it. */
export function unicodeEnabled(env: NodeJS.ProcessEnv = process.env) {
  if (env["ASSAY_ASCII"] === "1") return false;
  if (process.platform === "win32" && !env["WT_SESSION"] && !env["TERM_PROGRAM"]) return false;
  return true;
}

export interface Theme {
  readonly color: boolean;
  readonly unicode: boolean;
  readonly width: number;
  // Semantic, not decorative: callers say what a thing MEANS, so the
  // palette can change in one place and stay internally consistent.
  pass(s: string): string;
  fail(s: string): string;
  warn(s: string): string;
  muted(s: string): string;
  bold(s: string): string;
  heading(s: string): string;
  accent(s: string): string;
  code(s: string): string;
  /** Glyph for a check status. */
  glyph(kind: StatusKind): string;
  /**
   * Punctuation that is not ASCII.
   *
   * `ASSAY_ASCII=1` used to be half-honoured — only the status glyphs
   * and box characters consulted it, while the ellipsis, em dash, arrow
   * and middot were hardcoded, so six non-ASCII characters survived a
   * flag whose entire purpose is that none do.
   */
  readonly ellipsis: string;
  readonly arrow: string;
  readonly dot: string;
  readonly dash: string;
}

export type StatusKind = "pass" | "fail" | "warn" | "neutral" | "skip" | "error";

const wrap = (on: boolean, open: string, close: string) => (s: string) =>
  on ? `${ESC}${open}m${s}${ESC}${close}m` : s;

export function createTheme(
  opts: Partial<{ color: boolean; unicode: boolean; width: number }> = {},
): Theme {
  const color = opts.color ?? colorEnabled();
  const unicode = opts.unicode ?? unicodeEnabled();
  // Clamped: very wide terminals produce unreadable long lines, very
  // narrow ones break the layout entirely.
  // `COLUMNS` is honoured because it is the only way to control layout
  // in a pipe, where `process.stdout.columns` is undefined. The floor is
  // 40 rather than 60: a 45-column terminal was being handed 60-column
  // rules that it then hard-wrapped, which is worse than a narrow layout.
  const envWidth = Number(process.env["COLUMNS"]);
  const width = Math.max(
    40,
    Math.min(opts.width ?? (envWidth > 0 ? envWidth : (process.stdout.columns ?? 80)), 100),
  );

  const glyphs: Record<StatusKind, string> = unicode
    ? { pass: "✔", fail: "✘", warn: "▲", neutral: "–", skip: "·", error: "!" }
    : // Padded to equal width. `PASS` (4) beside `n/a` (3) ragged the
      // left edge of every row in the pass table.
      { pass: "PASS", fail: "FAIL", warn: "WARN", neutral: " n/a", skip: "SKIP", error: " ERR" };

  return {
    color,
    unicode,
    width,
    // 256-colour codes chosen to stay legible on BOTH light and dark
    // backgrounds — the most common complaint about coloured CLI output
    // is that it was only ever tested on one.
    pass: wrap(color, "38;5;35", "39"),
    fail: wrap(color, "38;5;167", "39"),
    warn: wrap(color, "38;5;179", "39"),
    muted: wrap(color, "38;5;245", "39"),
    bold: wrap(color, "1", "22"),
    // Closes with scoped codes, not a full reset: `\u001b[0m` cancels
    // every enclosing style too, so a heading nested inside any other
    // wrapper silently killed it.
    heading: wrap(color, "1;38;5;39", "22;39"),
    accent: wrap(color, "38;5;39", "39"),
    code: wrap(color, "38;5;141", "39"),
    glyph: (kind) => glyphs[kind],
    ellipsis: unicode ? "…" : "...",
    arrow: unicode ? "→" : "->",
    dot: unicode ? "·" : "*",
    dash: unicode ? "—" : "--",
  };
}

/** Colour a status glyph to match its meaning. */
export function statusGlyph(theme: Theme, kind: StatusKind): string {
  const g = theme.glyph(kind);
  switch (kind) {
    case "pass":
      return theme.pass(g);
    case "fail":
      return theme.fail(g);
    case "warn":
      return theme.warn(g);
    case "error":
      return theme.warn(g);
    default:
      return theme.muted(g);
  }
}

/**
 * A horizontal bar for a 0–100 score.
 *
 * Deliberately also prints the number. A bar alone is unreadable to
 * anyone using a screen reader and unusable when the output is piped,
 * so it is an accent on the figure rather than a replacement for it.
 */
export function scoreBar(theme: Theme, value: number, measured: boolean, cells = 18): string {
  // NOT the rule character. An unmeasured axis bar drawn with `─` was
  // visually identical to the section divider directly above it.
  if (!measured) return theme.muted(theme.unicode ? "·".repeat(cells) : ".".repeat(cells));
  const filled = Math.round((Math.max(0, Math.min(100, value)) / 100) * cells);
  const [full, empty] = theme.unicode ? ["█", "░"] : ["#", "."];
  const paint = value >= 80 ? theme.pass : value >= 50 ? theme.warn : theme.fail;
  // The TROUGH carries the grade colour at low scores, not just the
  // fill. With `filled === 0` the coloured span was empty and the whole
  // row rendered muted — so `safety 0` on an artifact shipping a
  // credential was the quietest line on the page, dimmer than a `care
  // 50` above it. Worst value, least ink.
  const troughPaint = value >= 50 ? theme.muted : paint;
  return paint(full.repeat(filled)) + troughPaint(empty.repeat(cells - filled));
}

/**
 * How many terminal CELLS a character occupies.
 *
 * `.length` counts UTF-16 code units, which is wrong twice over: an
 * emoji is two units and one glyph, and a CJK ideograph is one unit and
 * TWO cells. Every padded column was computed from `.length`, so a
 * Japanese summary or an emoji in a description ragged the whole table.
 *
 * East Asian Wide and Fullwidth blocks plus the emoji planes. Not
 * exhaustive — the full Unicode width table is thousands of entries —
 * but it covers everything an artifact realistically ships.
 */
function charWidth(cp: number): number {
  // Combining marks and zero-width characters occupy no cell.
  if (cp === 0x200b || (cp >= 0x0300 && cp <= 0x036f) || (cp >= 0xfe00 && cp <= 0xfe0f)) return 0;
  if (
    (cp >= 0x1100 && cp <= 0x115f) ||
    (cp >= 0x2e80 && cp <= 0x303e) ||
    (cp >= 0x3041 && cp <= 0x33ff) ||
    (cp >= 0x3400 && cp <= 0x4dbf) ||
    (cp >= 0x4e00 && cp <= 0x9fff) ||
    (cp >= 0xa000 && cp <= 0xa4cf) ||
    (cp >= 0xac00 && cp <= 0xd7a3) ||
    (cp >= 0xf900 && cp <= 0xfaff) ||
    (cp >= 0xfe30 && cp <= 0xfe6f) ||
    (cp >= 0xff00 && cp <= 0xff60) ||
    (cp >= 0xffe0 && cp <= 0xffe6) ||
    (cp >= 0x1f300 && cp <= 0x1f64f) ||
    (cp >= 0x1f900 && cp <= 0x1f9ff) ||
    (cp >= 0x20000 && cp <= 0x3fffd)
  ) {
    return 2;
  }
  return 1;
}

/** Strip ANSI so width maths is about glyphs, not escape bytes. */
function stripAnsi(s: string): string {
  return s.replace(/\u001b\[[0-9;]*m/g, "");
}

/** Visible width in terminal CELLS, ignoring ANSI. */
export function visibleLength(s: string): number {
  let w = 0;
  for (const ch of stripAnsi(s)) w += charWidth(ch.codePointAt(0)!);
  return w;
}

/**
 * Truncate to a CELL width, by grapheme rather than by code unit.
 *
 * `.slice()` cut surrogate pairs in half and emitted a lone replacement
 * character — including into the evidence excerpt for a malicious
 * install script, the worst possible place to print something the
 * reader cannot trust.
 */
export function truncateVisible(s: string, width: number, ellipsis = "\u2026"): string {
  if (visibleLength(s) <= width) return s;
  const budget = Math.max(0, width - visibleLength(ellipsis));
  let out = "";
  let w = 0;
  for (const ch of stripAnsi(s)) {
    const cw = charWidth(ch.codePointAt(0)!);
    if (w + cw > budget) break;
    out += ch;
    w += cw;
  }
  return out + ellipsis;
}

/** Soft-wrap prose to the theme width, with a hanging indent. */
export function wrapText(text: string, width: number, indent = ""): string {
  const out: string[] = [];
  let line = "";
  const push = () => {
    if (line) out.push(line);
    line = "";
  };

  for (const word of text.split(/\s+/).filter(Boolean)) {
    // A single token longer than the whole budget — a URL, a long file
    // path, a 66-character CJK name — used to be emitted whole and blew
    // the line past the terminal width. Hard-break it instead.
    let w = word;
    while (visibleLength(w) > width) {
      push();
      let head = "";
      for (const ch of w) {
        if (visibleLength(head) + charWidth(ch.codePointAt(0)!) > width) break;
        head += ch;
      }
      out.push(head);
      w = w.slice(head.length);
    }
    if (line && visibleLength(line) + visibleLength(w) + 1 > width) push();
    line = line ? `${line} ${w}` : w;
  }
  push();
  return out.join(`\n${indent}`);
}

export function padEndVisible(s: string, width: number): string {
  const pad = width - visibleLength(s);
  return pad > 0 ? s + " ".repeat(pad) : s;
}

/**
 * A live status line for slow work.
 *
 * Silent whenever stdout is not a terminal, so piping stays clean, and
 * it writes to STDERR so it never contaminates `--json` on stdout. A
 * behavioural run takes minutes; without this the tool looks hung, and
 * "is it working?" is the question that makes people kill it.
 */
export class Spinner {
  readonly #frames: string[];
  readonly #enabled: boolean;
  #timer: NodeJS.Timeout | null = null;
  #frame = 0;
  #text = "";
  #start = 0;

  constructor(
    private readonly theme: Theme,
    enabled = spinnerEnabled(),
  ) {
    this.#enabled = Boolean(enabled);
    this.#frames = theme.unicode
      ? ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
      : ["-", "\\", "|", "/"];
  }

  start(text: string): this {
    this.#text = text;
    this.#start = Date.now();
    if (!this.#enabled) {
      // Non-TTY still gets ONE line, so a CI log says what happened.
      process.stderr.write(`  ${text}\n`);
      return this;
    }
    this.#timer = setInterval(() => this.#render(), 90);
    this.#render();
    return this;
  }

  update(text: string): this {
    this.#text = text;
    if (!this.#enabled) process.stderr.write(`  ${text}\n`);
    return this;
  }

  /** Clear the line and stop. Safe to call twice. */
  stop(final?: string): void {
    if (this.#timer) {
      clearInterval(this.#timer);
      this.#timer = null;
      process.stderr.write(`\r${" ".repeat(Math.max(0, this.theme.width))}\r`);
    }
    if (final) process.stderr.write(`${final}\n`);
  }

  #render(): void {
    const f = this.#frames[this.#frame++ % this.#frames.length]!;
    const secs = Math.floor((Date.now() - this.#start) / 1000);
    // Elapsed time is shown because the honest answer to "is it stuck?"
    // is a number that keeps going up.
    const elapsed = secs > 2 ? this.theme.muted(` ${secs}s`) : "";
    const line = `\r  ${this.theme.accent(f)} ${this.#text}${elapsed}`;
    process.stderr.write(padEndVisible(line, this.theme.width));
  }
}

/** Box-drawing characters, or ASCII when unicode is unavailable. */
export function boxChars(theme: Theme) {
  return theme.unicode
    ? { h: "─", v: "│", tl: "╭", tr: "╮", bl: "╰", br: "╯" }
    : { h: "-", v: "|", tl: "+", tr: "+", bl: "+", br: "+" };
}
