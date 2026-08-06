/**
 * Provisioning the one dependency assay cannot speak for itself.
 *
 * Every model adapter talks HTTP directly, so none of them needs a
 * package. The E2B sandbox is the exception: its process API is
 * Connect-RPC streaming rather than a request/response endpoint, and
 * hand-rolling that would be a fragile reimplementation of a protocol
 * we do not control. So `e2b` stays a real package.
 *
 * What must NOT stay is the manual step. Telling someone to run
 *
 *     npm install --prefix ~/.assay/lib e2b
 *
 * after they have already installed the tool, entered a key and been
 * told the sandbox is configured, is an unfinished install wearing an
 * instruction.
 *
 * So provisioning hangs off the RESOLVER, not off the wizard. Any path
 * that needs the client fetches it — `assay setup` when you pick E2B,
 * and equally `assay run --behavioral` when the only thing you did was
 * export `E2B_API_KEY`. Wiring it to setup alone left the second path
 * still handing out npm commands, which is most of the way to nowhere:
 * environment variables are how CI configures everything.
 *
 * The bare `npm install e2b` this replaced was worse than nothing: a
 * release tarball unpacks to `~/.assay/lib` with no node_modules, so
 * the command installed the package into whatever directory the user
 * happened to be standing in, where assay would never resolve it. It
 * appeared to succeed and changed nothing.
 */
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

/**
 * The package root that owns assay's `node_modules`.
 *
 * `dist/vendor.js` → up one, which is the directory holding
 * package.json in both a tarball install and a source checkout.
 */
export function assayLibRoot(): string {
  return fileURLToPath(new URL("..", import.meta.url)).replace(/\/$/, "");
}

/** Is a package already resolvable from where assay runs? */
export function hasPackage(name: string): boolean {
  try {
    createRequire(import.meta.url).resolve(name);
    return true;
  } catch {
    return false;
  }
}

export interface InstallResult {
  ok: boolean;
  /** What to show the user when it did not work. */
  detail?: string;
}

/**
 * Install a package where assay can resolve it.
 *
 * Deliberately quiet on success and specific on failure: a user who
 * chose E2B wants a sandbox, not a build log, but one who has no npm
 * needs to know that is the problem rather than their key.
 */
export function installPackage(name: string, timeoutMs = 120_000): Promise<InstallResult> {
  return new Promise((resolve) => {
    const root = assayLibRoot();
    const child = spawn(
      "npm",
      ["install", "--prefix", root, name, "--no-audit", "--no-fund", "--loglevel", "error"],
      { stdio: ["ignore", "pipe", "pipe"] },
    );

    let stderr = "";
    child.stderr.on("data", (d: Buffer) => {
      stderr += d.toString();
    });
    child.stdout.on("data", () => {
      /* discarded: success is silent, and npm's progress is not ours to render */
    });

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolve({ ok: false, detail: `timed out after ${Math.round(timeoutMs / 1000)}s` });
    }, timeoutMs);

    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({
        ok: false,
        detail:
          (err as NodeJS.ErrnoException).code === "ENOENT"
            ? "npm is not installed, so the package cannot be fetched"
            : err.message,
      });
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) resolve({ ok: true });
      else resolve({ ok: false, detail: stderr.trim().split("\n").slice(-3).join("\n") });
    });
  });
}

/**
 * Packages assay may fetch for itself, and the version range it wants.
 *
 * An allowlist, not a free-form installer. Auto-installing whatever a
 * caller names would make this a remote-code-execution primitive
 * inside a security tool, which is not a trade worth making for
 * convenience. These are the two optional capabilities that genuinely
 * cannot be spoken over plain HTTP.
 */
const PROVISIONABLE: Record<string, { range: string; why: string }> = {
  e2b: {
    range: "e2b@^2.37.0",
    why: "the E2B sandbox client",
  },
  sigstore: {
    range: "sigstore@^5.0.0",
    why: "the Sigstore keyless-signing client",
  },
};

export function isProvisionable(name: string): boolean {
  return Object.hasOwn(PROVISIONABLE, name);
}

/**
 * Make a package available, installing it if it is not.
 *
 * This is the whole answer to "why should the user run npm at all?"
 * They should not. Asking someone who typed `--behavioral` to go and
 * hand-install a client into the tool's own lib directory is asking
 * them to finish an installation we shipped incomplete.
 *
 * It is deliberately NOT silent. The tool is about to write to disk and
 * talk to a registry on the user's behalf, and a security tool that
 * does that invisibly has no standing to complain about anyone else's
 * supply chain. One line, before and after.
 *
 * Consent is the `--behavioral` flag itself: it is opt-in, it already
 * costs money, and it cannot run without this. A user who did not ask
 * for a behavioral run never reaches here.
 */
export async function ensurePackage(
  name: string,
  say: (s: string) => void = () => {},
): Promise<InstallResult> {
  if (hasPackage(name)) return { ok: true };

  const spec = PROVISIONABLE[name];
  if (!spec) return { ok: false, detail: `"${name}" is not a package assay installs.` };

  say(`  Fetching ${spec.why} (${spec.range}) into ${assayLibRoot()}\n`);
  const r = await installPackage(spec.range);
  if (r.ok) say(`  Installed ${name}\n`);
  return r;
}

/**
 * What to say when we could not fetch it after trying.
 *
 * Only reached when the automatic attempt failed — offline, no npm, a
 * registry outage — so it names the manual command AND the escape
 * hatch that needs no package at all.
 */
export function provisionHint(name: string, detail?: string): string {
  const spec = PROVISIONABLE[name];
  return (
    `assay needs ${spec?.why ?? `the "${name}" package`} and could not install it` +
    `${detail ? ` — ${detail}` : ""}.\n\n` +
    `  Install it manually:  npm install --prefix ${assayLibRoot()} ${spec?.range ?? name}\n` +
    (name === "e2b" ? `  Or run locally with no package at all:  --sandbox podman\n` : "")
  );
}
