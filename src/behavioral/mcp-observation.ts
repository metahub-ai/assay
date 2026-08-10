/**
 * MCP-specific observations derived from a behavioral run.
 *
 * The behavioral tier is kind-agnostic — it drives anything and judges
 * the transcript. But an MCP server exposes structured protocol data no
 * other kind has: a typed tool catalog with safety annotations, a
 * JSON-RPC handshake, resources and prompts. This module turns that into
 * two verdicts the report can show, both PURE FUNCTIONS so they are
 * tested without a sandbox:
 *
 *   - assessConformance: does the server actually speak the protocol
 *     correctly — handshake, self-identification, at least one
 *     capability, well-formed tools?
 *   - annotationTruth: do the server's own safety annotations
 *     (readOnlyHint / destructiveHint) match what it says and does? A
 *     tool that declares itself read-only while its description says it
 *     writes — or while the runtime ledger saw the server mutate the
 *     filesystem — is misrepresenting itself to the safety UI that reads
 *     those hints.
 *
 * The declared-vs-description half is precise and always available. The
 * declared-vs-observed half is coarse (the ledger spans the whole
 * session, adversarial probes included) so it is reported as a softer
 * signal, never a blocking one — the same attribution rule the ledger
 * already follows.
 */

/** A tool's safety annotations, as the MCP spec defines them, plus
 *  whether it declared an input schema. All optional: annotations are a
 *  spec addition and a server may omit them. */
export interface McpToolAnnotation {
  name: string;
  description?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
  title?: string;
  hasInputSchema: boolean;
}

export interface ConformanceCheck {
  id: string;
  ok: boolean;
  detail: string;
}

export interface ConformanceReport {
  /** Fraction of applicable checks that passed, 0..1. */
  score: number;
  checks: ConformanceCheck[];
}

export interface McpObservation {
  conformance: ConformanceReport;
  tools: McpToolAnnotation[];
}

export interface ConformanceInput {
  initialize?: { protocolVersion?: string; serverInfo?: { name?: string } };
  tools: { name: string; hasInputSchema: boolean }[];
  hasResources: boolean;
  hasPrompts: boolean;
}

/** Protocol versions the current SDKs negotiate. Kept loose — the point
 *  is to catch an empty or garbage value, not to gatekeep new dates. */
const PROTOCOL_VERSION_RE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Score how correctly the server spoke MCP, from what the driver saw.
 *
 * Deterministic: every input here comes from the recorded handshake and
 * tool catalog, so two runs of the same server produce the same verdict.
 */
export function assessConformance(input: ConformanceInput): ConformanceReport {
  const checks: ConformanceCheck[] = [];
  const proto = input.initialize?.protocolVersion;
  checks.push({
    id: "handshake",
    ok: Boolean(input.initialize),
    detail: input.initialize
      ? "initialize returned a result"
      : "no initialize result — the handshake did not complete",
  });
  checks.push({
    id: "protocol-version",
    ok: typeof proto === "string" && PROTOCOL_VERSION_RE.test(proto),
    detail: proto ? `protocolVersion "${proto}"` : "no protocolVersion negotiated",
  });
  checks.push({
    id: "self-identifies",
    ok: Boolean(input.initialize?.serverInfo?.name),
    detail: input.initialize?.serverInfo?.name
      ? `serverInfo.name "${input.initialize.serverInfo.name}"`
      : "serverInfo.name missing — the server does not name itself",
  });
  const anyCapability = input.tools.length > 0 || input.hasResources || input.hasPrompts;
  checks.push({
    id: "exposes-capability",
    ok: anyCapability,
    detail: anyCapability
      ? `exposes ${input.tools.length} tool(s)${input.hasResources ? ", resources" : ""}${input.hasPrompts ? ", prompts" : ""}`
      : "exposes no tools, resources, or prompts — nothing to use",
  });
  if (input.tools.length > 0) {
    const unnamed = input.tools.filter((t) => !t.name || !t.name.trim());
    checks.push({
      id: "tools-named",
      ok: unnamed.length === 0,
      detail:
        unnamed.length === 0
          ? "every tool has a name"
          : `${unnamed.length} tool(s) returned with no name`,
    });
    const noSchema = input.tools.filter((t) => !t.hasInputSchema);
    checks.push({
      id: "tools-have-input-schema",
      ok: noSchema.length === 0,
      detail:
        noSchema.length === 0
          ? "every tool declares an inputSchema"
          : `${noSchema.length} of ${input.tools.length} tools omit inputSchema (the spec expects one)`,
    });
  }
  const passed = checks.filter((c) => c.ok).length;
  return { score: checks.length === 0 ? 0 : passed / checks.length, checks };
}

export interface AnnotationFinding {
  tool: string;
  /** The claim that is contradicted. */
  claim: string;
  /** What contradicts it. */
  contradiction: string;
  /** True when a runtime observation (not just the description) is the
   *  source — carries less certainty because the ledger is session-wide. */
  fromRuntime: boolean;
}

/** Verbs in a description that imply the tool changes state. */
const MUTATING_VERB =
  /\b(write|writes|create|creates|delete|deletes|remove|removes|update|updates|modify|modifies|insert|inserts|drop|drops|send|sends|post|posts|upload|uploads|execute|executes|run|runs|install|installs|overwrite|overwrites|rename|renames|move|moves|save|saves|store|stores|persist|persists|append|appends|log|logs)\b/i;

export interface ObservedSideEffects {
  wroteOrDeletedFiles: boolean;
  spawnedProcesses: boolean;
  networked: boolean;
}

/**
 * Cross-check the server's safety annotations against its own
 * descriptions and, when available, the runtime ledger.
 *
 * Two independent signals:
 *   1. Declared-vs-description (precise): a tool marked readOnlyHint:true
 *      whose description uses mutating verbs is contradicting itself in
 *      the two fields the model reads together.
 *   2. Declared-vs-observed (coarse): if EVERY tool claims to be
 *      read-only but the run observed the server writing files, spawning
 *      processes, or making network calls, the read-only claim as a whole
 *      is contradicted. Coarse because the ledger cannot attribute an
 *      effect to a specific tool call.
 */
export function annotationTruth(
  tools: McpToolAnnotation[],
  observed?: ObservedSideEffects,
): AnnotationFinding[] {
  const findings: AnnotationFinding[] = [];

  for (const t of tools) {
    if (t.readOnlyHint === true && t.description && MUTATING_VERB.test(t.description)) {
      const verb = MUTATING_VERB.exec(t.description)?.[0] ?? "mutate";
      findings.push({
        tool: t.name,
        claim: "readOnlyHint: true",
        contradiction: `its description says it "${verb}" — a state-changing verb`,
        fromRuntime: false,
      });
    }
  }

  // Coarse corroboration: a wholly-read-only server that the ledger saw
  // mutate. Only meaningful when there ARE read-only claims and NO tool
  // is annotated as writable (otherwise the effect is explained).
  const readOnly = tools.filter((t) => t.readOnlyHint === true);
  const anyWritable = tools.some((t) => t.readOnlyHint === false || t.destructiveHint === true);
  if (observed && readOnly.length > 0 && readOnly.length === tools.length && !anyWritable) {
    const effects: string[] = [];
    if (observed.wroteOrDeletedFiles) effects.push("wrote or deleted files");
    if (observed.spawnedProcesses) effects.push("spawned processes");
    if (observed.networked) effects.push("made network connections");
    if (effects.length > 0) {
      findings.push({
        tool: "(all tools)",
        claim: "every tool declares readOnlyHint: true",
        contradiction: `but the run observed the server ${effects.join(", ")}`,
        fromRuntime: true,
      });
    }
  }

  return findings;
}
