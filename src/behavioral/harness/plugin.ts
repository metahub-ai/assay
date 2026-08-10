/**
 * Plugin harness — runs a plugin bundle behaviorally inside the sandbox.
 *
 * A plugin bundles capabilities (skills / commands / subagents / hooks /
 * an MCP server) declared in a `plugin.json` (or `.claude-plugin/...`)
 * manifest. This harness:
 *
 *   1. installs the plugin's dependencies,
 *   2. verifies the manifest loads + parses,
 *   3. enumerates the bundled items, and
 *   4. **smoke-runs every bundled capability up to `EVAL_PLUGIN_CAPABILITY_CAP`
 *      (default 3)** — runMcpCase for each declared mcpServer, runSkillCase
 *      for each bundled skill. Earlier versions only ran the FIRST
 *      capability, which let a plugin whose first bundle was a trivial
 *      "init-config" skill earn a clean badge regardless of the other
 *      bundled items.
 *
 * The judge scores the combined transcript downstream.
 */
import type { LlmMessage, LlmProvider, LlmToolCall } from "../../ports.js";
import type { Sandbox } from "../../ports.js";
import type { EvalTestCase, Transcript } from "../types.js";
import { installDependencies } from "../install.js";
import { runMcpCase } from "./mcp.js";
import { runSkillCase } from "./skill.js";

const CAPABILITY_CAP = Math.max(1, Number(process.env.EVAL_PLUGIN_CAPABILITY_CAP ?? 3) || 3);

export interface PluginManifest {
  name?: string;
  skills?: unknown;
  commands?: unknown;
  subagents?: unknown;
  agents?: unknown;
  hooks?: unknown;
  mcpServers?: Record<string, { command?: string; args?: string[] }>;
}

export interface PluginHarnessInput {
  llm: LlmProvider;
  sandbox: Sandbox;
  /** Working directory inside the sandbox. Defaults to /workspace. */
  cwd?: string;
  /** Command that installs deps; defaults to `npm install`. */
  installCmd?: string;
  /**
   * Pre-fetched bundled SKILL.md body, when the publish pipeline captured
   * one. Used as the system prompt for the skill smoke-run.
   */
  skillDoc?: string;
  /** Runtime-recorder wrapper, forwarded to the capability sub-runs. */
  traceWrap?: import("../types.js").TraceWrap;
  test: EvalTestCase;
}

const MANIFEST_CANDIDATES = [".claude-plugin/plugin.json", "plugin.json", ".claude/plugin.json"];

/** Count the items declared under a manifest key (array or object map). */
function countItems(v: unknown): number {
  if (Array.isArray(v)) return v.length;
  if (v && typeof v === "object") return Object.keys(v).length;
  return 0;
}

/** Locate + parse the plugin manifest. Null when none loads. */
async function loadManifest(
  sandbox: Sandbox,
  cwd: string,
): Promise<{ path: string; manifest: PluginManifest } | null> {
  for (const rel of MANIFEST_CANDIDATES) {
    const raw = await sandbox.readFile(`${cwd}/${rel}`);
    if (raw === null) continue;
    try {
      return { path: rel, manifest: JSON.parse(raw) as PluginManifest };
    } catch {
      /* try the next candidate */
    }
  }
  return null;
}

/** Every declared MCP server command. */
function allMcpServerCmds(manifest: PluginManifest): string[] {
  const servers = manifest.mcpServers ?? {};
  const cmds: string[] = [];
  for (const key of Object.keys(servers)) {
    const s = servers[key];
    if (s?.command) cmds.push([s.command, ...(s.args ?? [])].join(" "));
  }
  return cmds;
}

/**
 * Enumerate bundled skill SKILL.md paths. Plugin manifests vary in
 * how they declare skills — either `skills: ["path/to/skill"]` or
 * `skills: { "name": { "path": "..." } }`. We normalize both shapes.
 */
function bundledSkillPaths(manifest: PluginManifest): string[] {
  const out: string[] = [];
  const v = manifest.skills;
  if (Array.isArray(v)) {
    for (const entry of v) {
      if (typeof entry === "string") out.push(entry);
      else if (entry && typeof entry === "object" && "path" in entry) {
        const p = (entry as { path?: unknown }).path;
        if (typeof p === "string") out.push(p);
      }
    }
  } else if (v && typeof v === "object") {
    for (const key of Object.keys(v)) {
      const entry = (v as Record<string, unknown>)[key];
      if (typeof entry === "string") out.push(entry);
      else if (entry && typeof entry === "object" && "path" in entry) {
        const p = (entry as { path?: unknown }).path;
        if (typeof p === "string") out.push(p);
      } else {
        // Convention fallback: `skills/<key>/SKILL.md`.
        out.push(`skills/${key}`);
      }
    }
  }
  return out;
}

/** Run one test case against the plugin bundle, capturing a transcript. */
export async function runPluginCase(input: PluginHarnessInput): Promise<Transcript> {
  const { sandbox, test } = input;
  const cwd = input.cwd ?? "/workspace";
  const messages: LlmMessage[] = [{ role: "user", content: test.prompt }];
  const toolCalls: LlmToolCall[] = [];
  const start = Date.now();

  // 1) install dependencies.
  const install = await installDependencies(sandbox, cwd, input.installCmd);
  messages.push({ role: "assistant", content: install.log });

  // 2) load + verify the manifest.
  const loaded = await loadManifest(sandbox, cwd);
  if (!loaded) {
    messages.push({ role: "assistant", content: "plugin manifest not found or unparseable" });
    return { messages, toolCalls, durationMs: Date.now() - start };
  }
  const { path, manifest } = loaded;

  // 3) enumerate bundled items.
  const counts = {
    skills: countItems(manifest.skills),
    commands: countItems(manifest.commands),
    subagents: countItems(manifest.subagents ?? manifest.agents),
    hooks: countItems(manifest.hooks),
    mcpServers: countItems(manifest.mcpServers),
  };
  messages.push({
    role: "assistant",
    content:
      `loaded manifest ${path} (${manifest.name ?? "unnamed"}): ` +
      `skills=${counts.skills} commands=${counts.commands} ` +
      `subagents=${counts.subagents} hooks=${counts.hooks} mcpServers=${counts.mcpServers}`,
  });

  // 4) smoke-run every bundled capability up to the cap. Each
  //    capability contributes its messages + toolCalls to the
  //    combined transcript. The judge scores the combined run.
  const capabilities: { kind: "mcp" | "skill"; label: string; cmd?: string; skillPath?: string }[] =
    [];
  for (const cmd of allMcpServerCmds(manifest)) {
    capabilities.push({ kind: "mcp", label: `mcp:${cmd}`, cmd });
  }
  for (const sp of bundledSkillPaths(manifest)) {
    capabilities.push({ kind: "skill", label: `skill:${sp}`, skillPath: sp });
  }
  if (capabilities.length === 0) {
    // No structured capabilities in the manifest — fall back to the
    // legacy single skill smoke against the pre-fetched SKILL.md.
    messages.push({
      role: "assistant",
      content: "no structured capabilities — running legacy skill smoke",
    });
    const sub = await runSkillCase({
      llm: input.llm,
      sandbox,
      skillDoc: input.skillDoc ?? `Plugin: ${manifest.name ?? "unnamed"}.`,
      cwd,
      ...(input.traceWrap ? { traceWrap: input.traceWrap } : {}),
      test,
    });
    messages.push(...sub.messages.filter((m) => m.role !== "user"));
    toolCalls.push(...sub.toolCalls);
    return { messages, toolCalls, durationMs: Date.now() - start };
  }

  const runnable = capabilities.slice(0, CAPABILITY_CAP);
  messages.push({
    role: "assistant",
    content: `smoke-running ${runnable.length} of ${capabilities.length} bundled capabilit${capabilities.length === 1 ? "y" : "ies"}: ${runnable.map((c) => c.label).join(", ")}`,
  });
  for (const cap of runnable) {
    if (cap.kind === "mcp" && cap.cmd) {
      const sub = await runMcpCase({
        llm: input.llm,
        sandbox,
        serverCmd: cap.cmd,
        cwd,
        ...(input.traceWrap ? { traceWrap: input.traceWrap } : {}),
        test,
      });
      messages.push({
        role: "assistant",
        content: `→ capability ${cap.label}`,
      });
      messages.push(...sub.messages.filter((m) => m.role !== "user"));
      toolCalls.push(...sub.toolCalls);
    } else if (cap.kind === "skill" && cap.skillPath) {
      // Try to load the bundled SKILL.md; fall back to the harness's
      // pre-fetched skillDoc if not present in the sandbox.
      let skillDoc = input.skillDoc ?? `Plugin: ${manifest.name ?? "unnamed"}.`;
      const candidate = `${cwd}/${cap.skillPath.replace(/^\/+/, "")}/SKILL.md`;
      const raw = await sandbox.readFile(candidate);
      if (raw && raw.length > 50) skillDoc = raw;
      const sub = await runSkillCase({
        llm: input.llm,
        sandbox,
        skillDoc,
        cwd,
        ...(input.traceWrap ? { traceWrap: input.traceWrap } : {}),
        test,
      });
      messages.push({
        role: "assistant",
        content: `→ capability ${cap.label}`,
      });
      messages.push(...sub.messages.filter((m) => m.role !== "user"));
      toolCalls.push(...sub.toolCalls);
    }
  }
  return { messages, toolCalls, durationMs: Date.now() - start };
}
