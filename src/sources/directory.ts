/**
 * A `SourceReader` over a local directory.
 *
 * This is the implementation that makes the framework's central promise
 * testable by an outsider: `assay run ./my-skill` reads through exactly
 * the same interface the hosted evaluation does, so a publisher can
 * reproduce a registry verdict locally instead of taking it on trust.
 * Without it every check is coupled to a transport and "local/remote
 * parity" is a slogan.
 */
import { createReadStream } from "node:fs";
import { readdir, readFile, readlink, realpath, stat } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import type { SourceReader, TreeEntry } from "../ports.js";

export interface DirectorySourceOptions {
  /**
   * Directories never descended into. These are developer-local or
   * transport-injected, so including them would make the same logical
   * artifact read differently depending on how it was fetched.
   */
  ignore?: string[];
  /**
   * Skip files larger than this when reading text. Reading a 2 GB blob
   * into a string to count its README words is a denial of service
   * against ourselves.
   */
  maxFileBytes?: number;
  /** Cap on entries walked, so a pathological tree cannot hang a run. */
  maxEntries?: number;
}

const DEFAULT_IGNORE = [
  ".git",
  "node_modules",
  ".venv",
  "venv",
  "__pycache__",
  ".mypy_cache",
  ".pytest_cache",
  "target",
  "dist",
  "build",
  ".next",
  ".turbo",
  ".assay-cache",
];

/**
 * What is genuinely NOT part of the artifact.
 *
 * Used for two things that must agree: copying the artifact into a
 * sandbox to run it, and computing its content digest. Both are asking
 * "what does this artifact actually consist of", and the answer is the
 * same.
 *
 * Deliberately narrower than `DEFAULT_IGNORE`. That list is right for
 * *linting* — build output should not be counted as the author's prose
 * or style. It is badly wrong for execution and catastrophic for
 * hashing.
 *
 * For execution: a package published to npm ships `dist/` and nothing
 * else, so filtering it delivered a package.json, a README and no code.
 *
 * For hashing it was worse. The subject digest is the foundation of
 * every integrity claim this tool makes — `assay verify --artifact`,
 * `diff`'s "same artifact digest", the case-cache key. Excluding `dist`
 * meant two npm packages differing ONLY in their shipped payload
 * digested identically. Demonstrated: a benign `console.log` and a
 * `dist/index.js` that curls ~/.aws/credentials to a remote host
 * produced the same sha256, and `assay diff` reported "Same artifact
 * digest… No regressions" and exited 0. That is precisely the
 * postmark-mcp attack the README opens with, invisible to the tool
 * built to catch it.
 *
 * What stays excluded is only what is genuinely reconstructible or
 * enormous, and what differs by how the artifact was fetched: dependency
 * trees, VCS metadata, caches, editor droppings.
 */
export const RUNTIME_IGNORE = [
  ".git",
  "node_modules",
  ".venv",
  "venv",
  "__pycache__",
  ".mypy_cache",
  ".pytest_cache",
  ".next",
  ".turbo",
  ".assay-cache",
];

const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_ENTRIES = 50_000;

export class DirectorySource implements SourceReader {
  readonly #root: string;
  readonly #ignore: Set<string>;
  readonly #maxFileBytes: number;
  readonly #maxEntries: number;
  #tree: TreeEntry[] | null = null;
  readonly #textCache = new Map<string, string | null>();

  constructor(root: string, opts: DirectorySourceOptions = {}) {
    this.#root = resolve(root);
    this.#ignore = new Set(opts.ignore ?? DEFAULT_IGNORE);
    this.#maxFileBytes = opts.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
    this.#maxEntries = opts.maxEntries ?? DEFAULT_MAX_ENTRIES;
  }

  /**
   * Resolve an artifact-relative path to an absolute one, refusing to
   * escape the root.
   *
   * A check is ordinary code from a stranger. `readFile("../../../etc/passwd")`
   * must not work, and neither must an absolute path — otherwise the
   * capability model leaks: a check that declared no capabilities could
   * still read the host filesystem.
   *
   * Lexical containment alone is NOT enough, and an earlier version of
   * this file got it wrong. `resolve()` does not follow symlinks but
   * `stat()`/`readFile()` do, so a symlink committed inside the
   * artifact — `escape-link -> /etc/passwd` — passed the lexical check
   * and was then read straight through. Containment has to be checked
   * against the REAL path.
   */
  #lexicallyContained(path: string): string | null {
    // Reject absolute paths outright rather than silently rebasing them.
    if (path.startsWith("/") || /^[A-Za-z]:[\\/]/.test(path)) return null;
    const abs = resolve(this.#root, path);
    const rel = relative(this.#root, abs);
    if (rel.startsWith("..") || rel.startsWith(`..${sep}`)) return null;
    return abs;
  }

  /**
   * Lexical containment plus a realpath check, so a symlink cannot
   * carry a read outside the artifact. Returns null when the path
   * escapes, does not exist, or cannot be resolved.
   */
  async #safeResolve(path: string): Promise<string | null> {
    const abs = this.#lexicallyContained(path);
    if (abs === null) return null;
    try {
      const realRoot = await realpath(this.#root);
      const real = await realpath(abs);
      const rel = relative(realRoot, real);
      if (rel.startsWith("..") || rel.startsWith(`..${sep}`)) return null;
      return real;
    } catch {
      // Missing, dangling symlink, or unreadable — all "no".
      return null;
    }
  }

  async listTree(): Promise<TreeEntry[]> {
    if (this.#tree) return this.#tree;
    const out: TreeEntry[] = [];
    const walk = async (dir: string): Promise<void> => {
      if (out.length >= this.#maxEntries) return;
      let entries;
      try {
        entries = await readdir(dir, { withFileTypes: true });
      } catch {
        // An unreadable directory is a fact about the environment, not
        // grounds for aborting the whole evaluation.
        return;
      }
      for (const e of entries) {
        if (out.length >= this.#maxEntries) return;
        if (this.#ignore.has(e.name)) continue;
        const abs = join(dir, e.name);
        const path = relative(this.#root, abs).split(sep).join("/");
        if (e.isDirectory()) {
          out.push({ path, type: "dir" });
          await walk(abs);
        } else if (e.isSymbolicLink()) {
          // Recorded but never followed. Following one could escape the
          // root, and resolving it would make the digest depend on the
          // host filesystem rather than on the artifact.
          //
          // The literal target IS read, though: it is the whole content
          // of a symlink, and without it a link to `~/.aws/credentials`
          // was indistinguishable from a link to `./README.md` — in the
          // digest and to every check.
          let target: string | undefined;
          try {
            target = await readlink(abs);
          } catch {
            target = undefined;
          }
          out.push({ path, type: "symlink", ...(target === undefined ? {} : { target }) });
        } else if (e.isFile()) {
          let size: number | undefined;
          let executable: boolean | undefined;
          try {
            const st = await stat(abs);
            size = st.size;
            executable = (st.mode & 0o111) !== 0;
          } catch {
            size = undefined;
          }
          out.push({
            path,
            type: "file",
            ...(size === undefined ? {} : { size }),
            ...(executable === undefined ? {} : { executable }),
          });
        }
      }
    };
    await walk(this.#root);
    out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    this.#tree = out;
    return out;
  }

  async readFile(path: string): Promise<string | null> {
    if (this.#textCache.has(path)) return this.#textCache.get(path) ?? null;
    const abs = await this.#safeResolve(path);
    let result: string | null = null;
    if (abs) {
      try {
        const info = await stat(abs);
        if (info.isFile() && info.size <= this.#maxFileBytes) {
          result = await readFile(abs, "utf8");
        }
      } catch {
        result = null;
      }
    }
    this.#textCache.set(path, result);
    return result;
  }

  async readBytes(path: string): Promise<Uint8Array | null> {
    const abs = await this.#safeResolve(path);
    if (!abs) return null;
    try {
      const info = await stat(abs);
      if (!info.isFile() || info.size > this.#maxFileBytes) return null;
      return new Uint8Array(await readFile(abs));
    } catch {
      return null;
    }
  }

  async exists(path: string): Promise<boolean> {
    // #safeResolve already realpaths, so a successful resolve means the
    // target exists AND is inside the artifact.
    return (await this.#safeResolve(path)) !== null;
  }

  /**
   * Streaming digest input, for files too large to hold in memory.
   *
   * Async so it gets the same realpath containment as every other read
   * — a sync variant could only do the lexical check, which is exactly
   * the hole that let a symlink escape.
   */
  async stream(path: string): Promise<NodeJS.ReadableStream | null> {
    const abs = await this.#safeResolve(path);
    return abs ? createReadStream(abs) : null;
  }
}
