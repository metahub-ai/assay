/**
 * Turning whatever the user typed into a directory to evaluate.
 *
 * The whole point is that `assay run` takes one argument and does the
 * obvious thing with it:
 *
 *     assay run .                                    a local directory
 *     assay run ./packages/my-skill
 *     assay run anthropics/skills                    owner/repo shorthand
 *     assay run anthropics/skills@v1.2.0             pinned to a ref
 *     assay run https://github.com/owner/repo
 *     assay run https://github.com/owner/repo/tree/main/skills/pdf
 *     assay run git@github.com:owner/repo.git
 *     assay run npm:@scope/package
 *     assay run npm:some-package@2.1.0
 *
 * Two design decisions are worth defending.
 *
 * **A local path always wins the `owner/repo` ambiguity.** `src/utils`
 * looks exactly like a GitHub shorthand. If it exists on disk we use the
 * disk, because silently cloning a stranger's repository when the user
 * meant a local folder is the worse failure by a wide margin. When
 * neither reading works the error says both things were tried.
 *
 * **npm packages are fetched from the registry tarball, never via
 * `npm pack`.** `npm pack` on a spec can execute `prepare` lifecycle
 * scripts from the package being fetched. Running arbitrary install
 * scripts from the artifact you were asked to *audit*, before the audit
 * starts, would be an unusually direct way to lose. Downloading the
 * tarball and extracting it runs nothing, and lets us check the
 * registry's integrity hash on the way past.
 */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, isAbsolute } from "node:path";
import {
  DEFAULT_REGISTRY,
  gitCoordinatesFor,
  parseRegistrySpec,
  resolveRegistryArtifact,
  type RegistryKind,
} from "./sources/registry.js";

export type TargetKind = "local" | "git" | "npm" | "registry";

export interface Target {
  kind: TargetKind;
  /** The string the user typed, preserved for the report. */
  spec: string;
  /** Local path, or the clone/fetch URL. */
  location: string;
  /** Branch, tag, or commit for git; version range for npm. */
  ref?: string;
  /** Evaluate only this subdirectory of the fetched tree. */
  subdir?: string;
  /** Human-readable name for headings. */
  display: string;
  /**
   * For a `registry` target: the artifact kind, when the user named it.
   *
   * The catalog lookup is keyed by kind and 404s on the wrong one, so
   * knowing it turns four probes into one.
   */
  registryKind?: string;
  /** For a `registry` target: which registry to ask. */
  registry?: string;
}

export class TargetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TargetError";
  }
}

/**
 * `[host/]owner/repo[//subdir][#ref]`
 *
 * `//` is a split point rather than a path separator, which is
 * Terraform's convention and the only inline form that is provably
 * unambiguous — a git server can legitimately host a repo at
 * `/network.git/modules/vpc`, so a single slash cannot tell you where
 * the repository ends and the subdirectory begins. degit had to
 * brute-force every split point once nested GitLab namespaces existed.
 *
 * `#` for the ref follows npm, npx, degit and Yarn. The split is not
 * arbitrary: `@` is used when the left side is a package NAME, `#` when
 * it is a REPO or URL, where it is the URL fragment and so composes
 * with full URLs and never collides with SSH's `user@host`. `@` is
 * accepted too, because people will type it.
 */
const GITHUB_SHORTHAND = /^(?:gh:)?([A-Za-z0-9][\w.-]*)\/([\w.-]+?)$/;

/**
 * Pull the optional `//subdir` and `#ref` off a shorthand.
 *
 * Both orders are accepted — `owner/repo//sub#ref` and
 * `owner/repo#ref//sub` — because both are things people type and
 * neither is ambiguous. `git check-ref-format` forbids consecutive
 * slashes in a ref, so a `//` appearing after the `#` can only be the
 * subdirectory marker and never part of the ref itself.
 *
 * Returns the bare `[host/]owner/repo` plus whatever was stripped.
 */
export function splitShorthand(raw: string): { base: string; subdir?: string; ref?: string } {
  let base = raw;
  let subdir: string | undefined;
  let ref: string | undefined;

  const hash = base.indexOf("#");
  if (hash !== -1) {
    const tail = base.slice(hash + 1);
    base = base.slice(0, hash);
    const dd = tail.indexOf("//");
    if (dd !== -1) {
      ref = tail.slice(0, dd);
      subdir = tail.slice(dd + 2);
    } else {
      ref = tail;
    }
  }

  const dd = base.indexOf("//");
  if (dd !== -1) {
    subdir = base.slice(dd + 2);
    base = base.slice(0, dd);
  }

  // `@ref`, but only when no `#` was used and only after the first
  // character, so a scoped-looking name is not mangled.
  if (ref === undefined) {
    const at = base.lastIndexOf("@");
    if (at > 0) {
      ref = base.slice(at + 1);
      base = base.slice(0, at);
    }
  }

  return {
    base,
    ...(subdir ? { subdir } : {}),
    ...(ref ? { ref } : {}),
  };
}

/**
 * A host, per Docker's rule: it is a host only if it contains a dot or
 * is exactly `localhost`. That dissolves the `a/b/c` ambiguity without
 * gh's arity counting, which reads `a/b/c` as host/owner/repo and so
 * cannot also support a subdirectory in that slot.
 */
function looksLikeHost(segment: string): boolean {
  return segment.includes(".") || segment === "localhost";
}

/**
 * Parse a spec into a target. Pure — no filesystem, no network.
 *
 * `existsLocally` is injected so the ambiguous `owner/repo` case is
 * decidable without this function needing to touch the disk, which
 * keeps it trivially testable.
 */
export function parseTarget(spec: string, existsLocally = false): Target {
  const raw = spec.trim();
  if (!raw) throw new TargetError("No target given. Try `assay run .`");

  // Unambiguous local forms, checked first so a directory literally
  // named `npm:foo` is still reachable as `./npm:foo`.
  if (
    raw === "." ||
    raw === ".." ||
    raw.startsWith("./") ||
    raw.startsWith("../") ||
    isAbsolute(raw)
  ) {
    return { kind: "local", spec: raw, location: resolve(raw), display: raw };
  }

  // A registry artifact. Resolved in `materialize`, not here, because
  // it needs a network round trip and `parseTarget` is synchronous and
  // pure — which is what lets the whole target grammar be unit-tested
  // without a server.
  if (raw.startsWith("metahub:") || raw.startsWith("registry:")) {
    const parsed = parseRegistrySpec(raw, process.env["ASSAY_REGISTRY"] || DEFAULT_REGISTRY);
    return {
      kind: "registry",
      spec: raw,
      location: parsed.slug,
      ...(parsed.kind ? { registryKind: parsed.kind } : {}),
      registry: parsed.registry,
      display: `metahub:${parsed.kind ? `${parsed.kind}/` : ""}${parsed.slug}`,
    };
  }

  if (raw.startsWith("npm:")) {
    const rest = raw.slice(4);
    // Scoped packages contain an `@` at position 0 that is not a version
    // separator, so search for the separator after the name.
    const at = rest.lastIndexOf("@");
    const scoped = rest.startsWith("@");
    const hasVersion = at > (scoped ? rest.indexOf("/") : 0);
    const name = hasVersion ? rest.slice(0, at) : rest;
    const version = hasVersion ? rest.slice(at + 1) : undefined;
    if (!name) throw new TargetError(`Not a valid npm package: ${raw}`);
    return {
      kind: "npm",
      spec: raw,
      location: name,
      ...(version ? { ref: version } : {}),
      display: `npm:${name}${version ? `@${version}` : ""}`,
    };
  }

  // SSH-style git remotes: git@host:owner/repo.git
  if (/^[\w.-]+@[\w.-]+:/.test(raw)) {
    return { kind: "git", spec: raw, location: raw, display: raw };
  }

  if (/^(https?|git\+https?|ssh):\/\//.test(raw)) {
    return parseUrl(raw);
  }

  // `[host/]owner/repo[//subdir][#ref]` — but a real directory on disk
  // always wins, because silently cloning a stranger's repository when
  // the user meant a local folder is much the worse failure.
  if (!existsLocally) {
    const { base, subdir, ref } = splitShorthand(raw);
    const parts = base.split("/");
    const host = parts.length > 2 && looksLikeHost(parts[0]!) ? parts.shift()! : "github.com";
    const short = GITHUB_SHORTHAND.exec(parts.join("/"));
    if (short) {
      const [, owner, repo] = short;
      return {
        kind: "git",
        spec: raw,
        location: `https://${host}/${owner}/${repo}.git`,
        ...(ref ? { ref } : {}),
        ...(subdir ? { subdir } : {}),
        display: `${owner}/${repo}${ref ? `@${ref}` : ""}${subdir ? `/${subdir}` : ""}`,
      };
    }

    // `owner/repo/skills/pdf` is the shape people reach for, and it
    // means four different things across gh, npm, degit and Terraform.
    // Deno's answer is the right one: reject it, and say what to type
    // instead, so the ergonomics survive without the ambiguity.
    const looksRepoish = /^[A-Za-z0-9][\w.-]*\/[\w.-]+\/.+/.test(base);
    if (looksRepoish) {
      const [owner, repo, ...rest] = base.split("/");
      throw new TargetError(
        `Ambiguous target "${raw}" — a single slash cannot separate the repository from a path inside it.\n` +
          `  For a subdirectory of a repository:  ${owner}/${repo}//${rest.join("/")}\n` +
          `  For a local directory:               ./${raw}`,
      );
    }
  }

  // Anything left is a bare relative path.
  return { kind: "local", spec: raw, location: resolve(raw), display: raw };
}

function parseUrl(raw: string): Target {
  let url: URL;
  try {
    url = new URL(raw.replace(/^git\+/, ""));
  } catch {
    throw new TargetError(`Not a valid URL: ${raw}`);
  }

  const segments = url.pathname.replace(/^\/+|\/+$/g, "").split("/");
  // `https://host/owner/repo#v1.2.0` — the fragment is the conventional
  // ref for a repo-shaped URL, and `new URL` has already split it off.
  const fragmentRef = url.hash ? url.hash.slice(1) : undefined;

  // GitHub, GitLab and Gitea all use /owner/repo/tree/<ref>/<subdir>,
  // which is the URL people actually copy out of a browser. Supporting
  // only the clone URL would mean telling users their link is wrong when
  // it is the most natural link they have.
  const isForge = /^(www\.)?(github\.com|gitlab\.com|codeberg\.org|bitbucket\.org)$/.test(
    url.hostname,
  );
  if (isForge && segments.length >= 2) {
    const [owner, repoRaw, marker, ref, ...rest] = segments;
    const repo = repoRaw!.replace(/\.git$/, "");
    const pathRef =
      (marker === "tree" || marker === "blob" || marker === "-") && ref ? ref : undefined;
    // A `/tree/<ref>/` in the path is more specific than a fragment, so
    // it wins if somehow both are present.
    const chosenRef = pathRef ?? fragmentRef;
    const subdir = rest.length ? rest.join("/") : undefined;
    return {
      kind: "git",
      spec: raw,
      location: `${url.protocol}//${url.hostname}/${owner}/${repo}.git`,
      ...(chosenRef ? { ref: chosenRef } : {}),
      ...(subdir ? { subdir } : {}),
      display: `${owner}/${repo}${chosenRef ? `@${chosenRef}` : ""}${subdir ? `/${subdir}` : ""}`,
    };
  }

  return { kind: "git", spec: raw, location: raw, display: url.hostname + url.pathname };
}

export interface Materialized {
  /** Directory to evaluate — already narrowed to `subdir`. */
  dir: string;
  /**
   * What was actually fetched, for the report.
   *
   * A grade over "whatever `main` was when I ran it" is not reproducible
   * and should not pretend to be, so the resolved commit or the
   * registry integrity hash is recorded rather than the ref that was
   * asked for.
   */
  provenance: {
    kind: TargetKind;
    spec: string;
    resolved?: string;
    url?: string;
    integrity?: string;
  };
  /**
   * The artifact kind, when a registry stated it authoritatively.
   *
   * Detection is a heuristic over file layout; a catalog entry is a
   * fact. When we have the fact, we use it.
   */
  registryKind?: string;
  /** The artifact's own name, when a registry supplied one. */
  registryName?: string;
  /** Remove any temporary directory. Always safe to call. */
  cleanup: () => Promise<void>;
}

const CLONE_TIMEOUT_MS = 120_000;
const FETCH_TIMEOUT_MS = 60_000;
/** Refuse anything implausible for an artifact; a tarball bomb is cheap to send. */
const MAX_TARBALL_BYTES = 100 * 1024 * 1024;

async function run(
  cmd: string,
  args: string[],
  opts: { cwd?: string; timeoutMs: number; env?: NodeJS.ProcessEnv },
): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(cmd, args, {
      ...(opts.cwd ? { cwd: opts.cwd } : {}),
      env: { ...process.env, ...opts.env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new TargetError(`\`${cmd}\` timed out after ${opts.timeoutMs / 1000}s`));
    }, opts.timeoutMs);
    child.stdout?.on("data", (d) => (stdout += d));
    child.stderr?.on("data", (d) => (stderr += d));
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(
        (err as NodeJS.ErrnoException).code === "ENOENT"
          ? new TargetError(`\`${cmd}\` is not installed, and is needed to fetch this target.`)
          : err,
      );
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolvePromise({ code: code ?? 1, stdout, stderr });
    });
  });
}

/**
 * Fetch the target and return a directory.
 *
 * `onProgress` exists because cloning a large repository takes tens of
 * seconds, and a tool that prints nothing during that looks hung.
 */
export async function materialize(
  target: Target,
  onProgress?: (message: string) => void,
): Promise<Materialized> {
  const noop = async () => {};
  switch (target.kind) {
    case "local": {
      const info = await stat(target.location).catch(() => null);
      if (!info?.isDirectory()) {
        // The `owner/repo` ambiguity resurfaces here as a confusing
        // "not found", so name both interpretations.
        const looksRemote = GITHUB_SHORTHAND.test(target.spec);
        throw new TargetError(
          `No directory at ${target.location}` +
            (looksRemote
              ? `\n  If you meant the GitHub repository, it could not be read as a local path either.` +
                `\n  Try the full URL: https://github.com/${target.spec}`
              : ""),
        );
      }
      return {
        dir: target.location,
        provenance: { kind: "local", spec: target.spec },
        cleanup: noop,
      };
    }
    case "git":
      return materializeGit(target, onProgress);
    case "npm":
      return materializeNpm(target, onProgress);
    case "registry":
      return materializeRegistry(target, onProgress);
  }
}

/**
 * Resolve a registry artifact to its source, then fetch that.
 *
 * Two steps, and the first one is the point: the catalog says which
 * commit it is serving, so the clone is pinned to that rather than to
 * a branch head. Without this the tool would grade a different tree
 * than the one a consumer installs, which is precisely the drift this
 * project exists to make visible.
 */
async function materializeRegistry(
  target: Target,
  onProgress?: (message: string) => void,
): Promise<Materialized> {
  onProgress?.(`Resolving ${target.display}`);
  const artifact = await resolveRegistryArtifact({
    slug: target.location,
    ...(target.registryKind ? { kind: target.registryKind as RegistryKind } : {}),
    registry: target.registry ?? DEFAULT_REGISTRY,
  });

  const git = gitCoordinatesFor(artifact);
  onProgress?.(
    `${artifact.kind} ${artifact.slug}${artifact.version ? ` v${artifact.version}` : ""} ` +
      `${git.pinned ? "pinned to" : "at"} ${(git.ref ?? "HEAD").slice(0, 12)}`,
  );

  const fetched = await materializeGit(
    {
      kind: "git",
      spec: target.spec,
      location: git.url,
      ...(git.ref ? { ref: git.ref } : {}),
      ...(git.subdir ? { subdir: git.subdir } : {}),
      display: target.display,
    },
    onProgress,
  );

  // Report it as what the user asked for — a registry artifact — while
  // keeping the resolved commit that makes it checkable.
  return {
    ...fetched,
    provenance: {
      ...fetched.provenance,
      kind: "registry",
      spec: target.spec,
      url: git.url,
    },
    registryKind: artifact.kind,
    registryName: artifact.slug,
  };
}

async function materializeGit(
  target: Target,
  onProgress?: (m: string) => void,
): Promise<Materialized> {
  const dir = await mkdtemp(join(tmpdir(), "assay-git-"));
  const cleanup = () => rm(dir, { recursive: true, force: true });

  onProgress?.(`Cloning ${target.display}`);
  const args = ["clone", "--depth", "1", "--quiet"];
  if (target.ref) args.push("--branch", target.ref);
  args.push(target.location, dir);

  const env = {
    // Without this a private or mistyped repository does not fail — git
    // blocks forever on a credential prompt that nobody is watching.
    GIT_TERMINAL_PROMPT: "0",
    GIT_ASKPASS: "echo",
    // Submodules are not fetched (no --recurse-submodules): they are a
    // separate trust decision and we should not make it silently.
    GIT_CONFIG_NOSYSTEM: "1",
  };

  let result = await run("git", args, { timeoutMs: CLONE_TIMEOUT_MS, env });

  // `--branch` rejects a full commit SHA, which is the ref most worth
  // supporting. Fall back to a full clone and check it out.
  if (
    result.code !== 0 &&
    target.ref &&
    /not found in upstream|Remote branch/i.test(result.stderr)
  ) {
    // Fetch just that one commit rather than the whole history.
    //
    // `git clone --branch` rejects a full SHA, and the obvious fallback
    // — clone everything, then check out — downloads a project's entire
    // history to read one directory. That cost is not hypothetical:
    // every artifact resolved through a registry is pinned to a
    // published SHA, so this path runs on every single one, and it
    // scales with the repository rather than with the artifact.
    //
    // `fetch --depth 1 <sha>` needs the server to allow fetching an
    // arbitrary object; GitHub does. When it does not, fall through to
    // the full clone, which always works.
    onProgress?.(`Fetching commit ${target.ref.slice(0, 12)}`);
    await rm(dir, { recursive: true, force: true });
    await mkdir(dir, { recursive: true });

    const shallow =
      (await run("git", ["init", "--quiet"], { cwd: dir, timeoutMs: CLONE_TIMEOUT_MS, env }))
        .code === 0 &&
      (
        await run("git", ["remote", "add", "origin", target.location], {
          cwd: dir,
          timeoutMs: CLONE_TIMEOUT_MS,
          env,
        })
      ).code === 0 &&
      (
        await run("git", ["fetch", "--depth", "1", "--quiet", "origin", target.ref], {
          cwd: dir,
          timeoutMs: CLONE_TIMEOUT_MS,
          env,
        })
      ).code === 0 &&
      (
        await run("git", ["checkout", "--quiet", "FETCH_HEAD"], {
          cwd: dir,
          timeoutMs: CLONE_TIMEOUT_MS,
          env,
        })
      ).code === 0;

    if (shallow) {
      result = { code: 0, stdout: "", stderr: "" };
    } else {
      onProgress?.(`Server would not serve that commit alone — fetching full history`);
      await rm(dir, { recursive: true, force: true });
      result = await run("git", ["clone", "--quiet", target.location, dir], {
        timeoutMs: CLONE_TIMEOUT_MS,
        env,
      });
      if (result.code === 0) {
        const co = await run("git", ["checkout", "--quiet", target.ref], {
          cwd: dir,
          timeoutMs: CLONE_TIMEOUT_MS,
          env,
        });
        if (co.code !== 0) {
          await cleanup();
          throw new TargetError(`No such ref "${target.ref}" in ${target.display}`);
        }
      }
    }
  }

  if (result.code !== 0) {
    await cleanup();
    const stderr = result.stderr.trim();
    if (/Authentication|could not read Username|Permission denied/i.test(stderr)) {
      throw new TargetError(
        `Cannot access ${target.display} — it is private, or the credentials are missing.\n` +
          `  Assay does not prompt for credentials. Clone it yourself and evaluate the local path.`,
      );
    }
    if (/not found|does not exist|Repository not found/i.test(stderr)) {
      throw new TargetError(`Repository not found: ${target.display}`);
    }
    throw new TargetError(`git clone failed: ${stderr || `exit ${result.code}`}`);
  }

  // The exact commit, not the ref that was asked for. A ref moves; a
  // report that says "main" is a report nobody can reproduce.
  const head = await run("git", ["rev-parse", "HEAD"], {
    cwd: dir,
    timeoutMs: 10_000,
    env,
  });
  const commit = head.code === 0 ? head.stdout.trim() : undefined;

  let evalDir = dir;
  if (target.subdir) {
    evalDir = resolve(dir, target.subdir);
    // A subdir out of the clone would be a path-traversal foothold from
    // a URL, so confirm containment rather than trusting the string.
    if (!evalDir.startsWith(dir)) {
      await cleanup();
      throw new TargetError(`Subdirectory escapes the repository: ${target.subdir}`);
    }
    const info = await stat(evalDir).catch(() => null);
    if (!info?.isDirectory()) {
      // Repositories reorganise, and a URL someone saved six months ago
      // is the most likely way to land here. Listing what IS at the
      // nearest existing level turns a dead end into one retry.
      const suggestion = await nearestListing(dir, target.subdir);
      await cleanup();
      throw new TargetError(
        `No directory "${target.subdir}" in ${target.display}` +
          (suggestion ? `\n${suggestion}` : ""),
      );
    }
  }

  return {
    dir: evalDir,
    provenance: {
      kind: "git",
      spec: target.spec,
      url: target.location,
      ...(commit ? { resolved: commit } : {}),
    },
    cleanup,
  };
}

/**
 * Walk up the requested path to the deepest part that does exist, and
 * list its subdirectories.
 */
async function nearestListing(root: string, subdir: string): Promise<string | null> {
  const { readdir } = await import("node:fs/promises");
  const parts = subdir.split("/").filter(Boolean);
  for (let depth = parts.length - 1; depth >= 0; depth--) {
    const probe = depth === 0 ? root : join(root, ...parts.slice(0, depth));
    const entries = await readdir(probe, { withFileTypes: true }).catch(() => null);
    if (!entries) continue;
    const dirs = entries
      .filter((e) => e.isDirectory() && !e.name.startsWith("."))
      .map((e) => e.name)
      .sort();
    if (!dirs.length) continue;
    const prefix = parts.slice(0, depth).join("/");
    const shown = dirs.slice(0, 12);
    return (
      `  Available under ${prefix ? `"${prefix}"` : "the repository root"}:\n` +
      `    ${shown.join(", ")}${dirs.length > shown.length ? `, … (${dirs.length - shown.length} more)` : ""}`
    );
  }
  return null;
}

interface NpmManifest {
  "dist-tags"?: Record<string, string>;
  versions?: Record<string, { dist?: { tarball?: string; integrity?: string; shasum?: string } }>;
}

async function materializeNpm(
  target: Target,
  onProgress?: (m: string) => void,
): Promise<Materialized> {
  const registry = (process.env["npm_config_registry"] ?? "https://registry.npmjs.org").replace(
    /\/+$/,
    "",
  );
  const name = target.location;
  onProgress?.(`Resolving ${target.display}`);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  let manifest: NpmManifest;
  try {
    const res = await fetch(`${registry}/${name.replace("/", "%2f")}`, {
      signal: controller.signal,
      headers: { accept: "application/json" },
    });
    if (res.status === 404) throw new TargetError(`No such npm package: ${name}`);
    if (!res.ok) throw new TargetError(`Registry returned HTTP ${res.status} for ${name}`);
    manifest = (await res.json()) as NpmManifest;
  } finally {
    clearTimeout(timer);
  }

  const wanted = target.ref ?? manifest["dist-tags"]?.["latest"];
  // Exact versions only. Resolving a range would mean implementing
  // semver ordering here, and quietly picking a different version than
  // the user believes they graded is worse than saying so.
  const version = wanted && manifest.versions?.[wanted] ? wanted : undefined;
  if (!version) {
    const available = Object.keys(manifest.versions ?? {})
      .slice(-5)
      .join(", ");
    throw new TargetError(
      (wanted ? `No published version "${wanted}" of ${name}.` : `${name} publishes no versions.`) +
        (available ? `\n  Recent versions: ${available}` : ""),
    );
  }

  const dist = manifest.versions![version]!.dist;
  if (!dist?.tarball) throw new TargetError(`${name}@${version} has no downloadable tarball`);

  onProgress?.(`Downloading ${name}@${version}`);
  const dir = await mkdtemp(join(tmpdir(), "assay-npm-"));
  const cleanup = () => rm(dir, { recursive: true, force: true });

  try {
    const res = await fetch(dist.tarball);
    if (!res.ok) throw new TargetError(`Tarball download failed: HTTP ${res.status}`);
    const body = Buffer.from(await res.arrayBuffer());
    if (body.byteLength > MAX_TARBALL_BYTES) {
      throw new TargetError(`Tarball is larger than ${MAX_TARBALL_BYTES / 1024 / 1024}MB`);
    }

    // Integrity is checked, not assumed. This is a tool whose entire
    // premise is that supply-chain provenance matters; skipping the hash
    // the registry hands us would be embarrassing.
    if (dist.integrity) {
      const [algo, expected] = dist.integrity.split("-");
      if (algo && expected) {
        const actual = createHash(algo).update(body).digest("base64");
        if (actual !== expected) {
          throw new TargetError(
            `Integrity check FAILED for ${name}@${version}.\n` +
              `  The registry's ${algo} hash does not match the bytes received.`,
          );
        }
      }
    }

    const tarball = join(dir, "package.tgz");
    await writeFile(tarball, body);
    // npm tarballs are all rooted at `package/`. GNU tar and bsdtar both
    // refuse absolute paths and `..` members by default, so extraction
    // cannot write outside the destination.
    const extracted = join(dir, "package");
    const untar = await run("tar", ["-xzf", tarball, "-C", dir], { timeoutMs: FETCH_TIMEOUT_MS });
    if (untar.code !== 0)
      throw new TargetError(`Could not extract tarball: ${untar.stderr.trim()}`);

    const info = await stat(extracted).catch(() => null);
    const evalDir = info?.isDirectory() ? extracted : dir;

    return {
      dir: evalDir,
      provenance: {
        kind: "npm",
        spec: target.spec,
        resolved: `${name}@${version}`,
        url: dist.tarball,
        ...(dist.integrity ? { integrity: dist.integrity } : {}),
      },
      cleanup,
    };
  } catch (err) {
    await cleanup();
    throw err;
  }
}
