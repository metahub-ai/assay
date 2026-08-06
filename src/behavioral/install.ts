/**
 * Dependency installation for the behavioral harnesses.
 *
 * Two things went wrong with a bare `npm install`, and they pull in the
 * same direction.
 *
 * **It executes the artifact's lifecycle scripts.** `preinstall`,
 * `install`, `postinstall` and `prepare` all run, from the package we
 * were asked to *audit*, before the audit has started. The fetch path in
 * `target.ts` already refuses to use `npm pack` for exactly this reason,
 * and `no-install-scripts` reports install hooks as a supply-chain risk
 * — so running them here contradicted both. The sandbox contains the
 * damage, which is why this was a posture problem rather than a
 * catastrophe, but "we sandbox it" is a poor answer when not running it
 * costs nothing.
 *
 * **It broke published packages.** A package published to npm ships its
 * built `dist/` and omits `src/` and `tsconfig.json`. Its `prepare`
 * script still says `tsc`, so on a published tarball `npm install` runs
 * a build with nothing to compile: `tsc` prints its help text, exits
 * non-zero, and the install fails. The official
 * `@modelcontextprotocol/server-everything` failed exactly this way and
 * was scored 0/10 for correctness — a working reference server marked
 * behaviourally broken by our harness.
 *
 * So: install with `--ignore-scripts`, then build ONLY if the entry
 * point is still missing afterwards, which is the git-checkout case
 * where a build is genuinely required. The build becomes a visible,
 * separately-reported step instead of a side effect hidden inside
 * install.
 */
import { SandboxInfraError, type Sandbox } from "../ports.js";

export interface InstallOutcome {
  /** Combined log for the transcript. */
  log: string;
  /** True when dependencies are usable. */
  ok: boolean;
}

const INSTALL_TIMEOUT_MS = 180_000;
const BUILD_TIMEOUT_MS = 180_000;

/**
 * Does the package declare an entry point that does not exist yet?
 *
 * That is the signal that a build step is genuinely required, and it is
 * cheap to check.
 */
async function needsBuild(sandbox: Sandbox, cwd: string): Promise<boolean> {
  const probe = await sandbox.exec(
    `node -e "const p=require('./package.json');` +
      `const f=p.bin?(typeof p.bin==='string'?p.bin:Object.values(p.bin)[0]):p.main;` +
      `if(!f){process.exit(1)}` +
      `process.exit(require('fs').existsSync(f)?1:0)"`,
    { cwd, timeoutMs: 20_000 },
  );
  return probe.exitCode === 0;
}

/**
 * Install dependencies without running the artifact's own scripts.
 */
export async function installDependencies(
  sandbox: Sandbox,
  cwd: string,
  installCmd?: string,
): Promise<InstallOutcome> {
  // An explicitly configured command is the caller's business; they may
  // have a good reason and they own the consequences.
  const cmd = installCmd ?? "npm install --ignore-scripts --no-audit --no-fund";
  const install = await sandbox.exec(cmd, { cwd, timeoutMs: INSTALL_TIMEOUT_MS });
  let log = `install exit=${install.exitCode}\n${install.stdout || install.stderr}`.trim();

  if (install.exitCode !== 0) {
    // A failed dependency install is almost always OUR problem — no
    // egress from the sandbox, a corporate proxy, a private registry, an
    // npm rate limit. THROWN rather than returned, because the previous
    // version returned an `ok:false` with an `infraHint` that no caller
    // ever read: all three harnesses logged the message and carried on,
    // the server could not start, and the judge graded a transcript of
    // our own failure as the artifact misbehaving.
    //
    // `SandboxInfraError` is caught by `runBehavioralEval` and becomes
    // `infraFailure`, which `toCheckResult` renders as `error` — never
    // as a verdict about someone else's code.
    throw new SandboxInfraError(
      install.timedOut
        ? `Dependency install timed out after ${INSTALL_TIMEOUT_MS / 1000}s inside the sandbox.`
        : `Dependency install failed inside the sandbox (exit ${install.exitCode}). ` +
            `This is an environment failure, not an artifact defect.\n${log}`,
    );
  }

  if (installCmd) return { log, ok: true };

  // Only now, and only if something is actually missing.
  if (await needsBuild(sandbox, cwd)) {
    const build = await sandbox.exec("npm run build --if-present", {
      cwd,
      timeoutMs: BUILD_TIMEOUT_MS,
    });
    log +=
      `\nbuild exit=${build.exitCode}\n${(build.stdout || build.stderr).slice(0, 2000)}`.trimEnd();
    if (build.exitCode !== 0) {
      // The artifact declares an entry point it cannot produce. That IS
      // an artifact defect, so it is not flagged as infrastructure —
      // but the harness continues, because the server may still start.
      return { log, ok: true };
    }
  }

  return { log, ok: true };
}
