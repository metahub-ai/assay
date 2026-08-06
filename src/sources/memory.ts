/**
 * In-memory source. The reference `SourceReader` implementation and
 * the one the test suite runs against.
 *
 * Its existence is a design check: if a check can only be tested by
 * pointing it at a real GitHub repo, the check is coupled to a
 * transport and the framework has failed at the thing it is for. Every
 * core check must be testable from a plain object literal.
 */
import type { SourceReader, TreeEntry } from "../ports.js";

export class MemorySource implements SourceReader {
  readonly #files: Map<string, string>;

  constructor(files: Record<string, string>) {
    this.#files = new Map(Object.entries(files));
  }

  async listTree(): Promise<TreeEntry[]> {
    const entries: TreeEntry[] = [];
    const dirs = new Set<string>();
    for (const [path, contents] of this.#files) {
      entries.push({ path, type: "file", size: Buffer.byteLength(contents, "utf8") });
      // Synthesize parent directories so tree consumers see the same
      // shape a real filesystem would present.
      const parts = path.split("/");
      for (let i = 1; i < parts.length; i++) dirs.add(parts.slice(0, i).join("/"));
    }
    for (const d of dirs) entries.push({ path: d, type: "dir" });
    return entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  }

  async readFile(path: string): Promise<string | null> {
    return this.#files.get(path) ?? null;
  }

  async readBytes(path: string): Promise<Uint8Array | null> {
    const text = this.#files.get(path);
    return text === undefined ? null : Buffer.from(text, "utf8");
  }

  async exists(path: string): Promise<boolean> {
    return this.#files.has(path);
  }
}
