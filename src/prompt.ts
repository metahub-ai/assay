/**
 * Minimal interactive prompts.
 *
 * Hand-rolled for the same reason as `term.ts`: a security tool that
 * flags dependency risk should not pull in a prompt library and its
 * transitive tree to read one line of input.
 *
 * Two properties matter more than polish. **It must refuse to run
 * without a TTY** rather than hanging forever waiting on stdin that
 * will never arrive — a wizard that blocks a CI job is worse than one
 * that errors. And **secrets must never echo**, including into shell
 * history or a screen recording.
 */
import { createInterface } from "node:readline/promises";

export class NotInteractiveError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotInteractiveError";
  }
}

export function isInteractive(): boolean {
  return Boolean(process.stdin.isTTY && process.stdout.isTTY);
}

function assertInteractive(): void {
  if (!isInteractive()) {
    throw new NotInteractiveError(
      "This needs an interactive terminal.\n" +
        "  In CI, set the environment variables directly instead — see `assay doctor`.",
    );
  }
}

/** Ask a free-text question. Returns the default when input is empty. */
export async function ask(question: string, fallback = ""): Promise<string> {
  assertInteractive();
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const hint = fallback ? ` (${fallback})` : "";
    const answer = await rl.question(`${question}${hint}: `);
    return answer.trim() || fallback;
  } catch (err) {
    // Ctrl-D closes stdin, and readline surfaces that as "Aborted with
    // Ctrl+D" — a raw library error that reaches the user as a crash.
    // It is a normal way to leave a prompt, so it becomes the same
    // cancellation Ctrl-C produces.
    if (/Aborted|closed/i.test((err as Error).message)) throw new Error("cancelled");
    throw err;
  } finally {
    rl.close();
  }
}

/**
 * Ask for a secret without echoing it.
 *
 * Raw mode, reading byte by byte, printing a bullet per character so
 * there is still feedback that typing registered. Ctrl-C is handled
 * explicitly — in raw mode the terminal does not generate SIGINT, so
 * without this the user cannot escape the prompt.
 */
export async function askSecret(question: string): Promise<string> {
  assertInteractive();
  process.stdout.write(`${question}: `);
  const stdin = process.stdin;
  const wasRaw = stdin.isRaw ?? false;
  stdin.setRawMode(true);
  stdin.resume();

  return new Promise<string>((resolve, reject) => {
    let value = "";
    const cleanup = () => {
      stdin.setRawMode(wasRaw);
      stdin.pause();
      stdin.removeListener("data", onData);
    };
    const onData = (chunk: Buffer) => {
      for (const byte of chunk) {
        switch (byte) {
          case 3: // Ctrl-C
            cleanup();
            process.stdout.write("\n");
            reject(new Error("cancelled"));
            return;
          case 13: // Enter
          case 10:
            cleanup();
            process.stdout.write("\n");
            resolve(value);
            return;
          case 127: // Backspace
          case 8:
            if (value.length > 0) {
              value = value.slice(0, -1);
              process.stdout.write("\b \b");
            }
            break;
          default:
            // Ignore control characters; a pasted key can contain them
            // and they would corrupt the value invisibly.
            if (byte >= 32) {
              value += String.fromCharCode(byte);
              process.stdout.write("•");
            }
        }
      }
    };
    stdin.on("data", onData);
  });
}

export interface Choice<T> {
  value: T;
  label: string;
  hint?: string;
}

/**
 * Numbered single-select.
 *
 * Numbered rather than arrow-key driven on purpose: it works over SSH,
 * in a `screen` session, on Windows, and with a screen reader, none of
 * which are reliable for cursor-addressed menus. The interaction is
 * duller and works everywhere.
 */
export async function select<T>(
  question: string,
  choices: readonly Choice<T>[],
  opts: { defaultIndex?: number; render?: (s: string) => string } = {},
): Promise<T> {
  assertInteractive();
  const paint = opts.render ?? ((s: string) => s);
  const def = opts.defaultIndex ?? 0;

  process.stdout.write(`\n  ${question}\n\n`);
  choices.forEach((c, i) => {
    const marker = i === def ? paint("›") : " ";
    const hint = c.hint ? `  ${c.hint}` : "";
    process.stdout.write(`  ${marker} ${paint(String(i + 1))}. ${c.label}${hint}\n`);
  });
  process.stdout.write("\n");

  for (;;) {
    const raw = await ask(`  Choose 1-${choices.length}`, String(def + 1));
    const idx = Number(raw) - 1;
    if (Number.isInteger(idx) && idx >= 0 && idx < choices.length) return choices[idx]!.value;
    process.stdout.write(`  Not a valid choice.\n`);
  }
}

export async function confirm(question: string, fallback = true): Promise<boolean> {
  const answer = await ask(`${question} [${fallback ? "Y/n" : "y/N"}]`, fallback ? "y" : "n");
  return /^y/i.test(answer);
}
