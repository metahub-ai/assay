# Changelog

All notable changes to `@metahub-ai/assay` are documented here. This project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html); while on
`0.x`, minor versions may carry breaking changes.

## [0.2.6] — 2026-08-21

### Added

- **NVIDIA API Catalog provider** (`--provider nvidia`). NVIDIA's
  build.nvidia.com hosts 100+ foundation models (Llama, Nemotron,
  DeepSeek, Qwen, Mistral, GLM, …) behind a single OpenAI-compatible
  endpoint reached with a free-tier `nvapi-` key, so it drops in as a
  first-class provider alongside anthropic/openai/openrouter/local.
  Configure with `NVIDIA_API_KEY`; pin models with `NVIDIA_JUDGE_MODEL`
  / `NVIDIA_DRIVER_MODEL` (defaults: `meta/llama-3.3-70b-instruct` for
  the judge, `meta/llama-3.1-8b-instruct` for the driver — set the exact
  ids from each model's card). Base URL and key are resolved per call,
  so changing the env takes effect on the next run.

## [0.2.5] — 2026-08-21

The SkillEvaluator-alignment release: bring Assay's skill grading to parity
with NVIDIA SkillEvaluator on the axes that belong in a single-artifact,
offline evaluator, and be explicit about the two that do not.

### Added

- **Five-dimension skill scorecard**, aligned with NVIDIA SkillEvaluator so a
  skill's result can be read against theirs like for like:
  **correctness · discoverability · effectiveness · efficiency · security**,
  each 0–10. Four of the five are a projection of signals Assay already
  computes (the judge's `correctness`, `instruction_adherence`, `latency`, and
  `safety`); the scorecard is surfaced as `result.scorecard`, as
  `skill_*` report metrics, and as a one-line summary. Skill-only.
- **Discoverability judgement.** A dedicated, skill-only judge dimension asking
  whether the skill activated APPROPRIATELY for a task — engaging a relevant one
  and staying out of an irrelevant one. Requested only for a skill's
  non-adversarial cases, so every other kind's four-dimension verdict is
  unchanged.
- **Case taxonomy.** Cases now carry an optional `caseType` —
  `explicit | implicit | contextual | negative` — matching SkillEvaluator's
  dataset shape. Synthesis produces a labelled spread for skills including at
  least one out-of-scope `negative` case, which is what makes discoverability a
  precision measure and not merely a recall one. Author-supplied `evals.json`
  may set `caseType` too.
- **Uplift is ON by default for skills.** The with/without "Skill Lift"
  measurement (previously opt-in via `--uplift`) now runs by default for the one
  kind it applies to, feeding the scorecard's effectiveness read; waive it with
  `--no-uplift`. Its delta is carried on the scorecard as `lift`.
- **`no-exposed-pii` check** (all kinds). Flags personal data shipped inside an
  artifact, confined to shapes that pass a validity test — a Luhn-valid payment
  card number and a structurally-valid US SSN — so a version string or an id is
  never mistaken for private data. Emails and phone numbers are deliberately not
  matched (an author contact is legitimate). As with secrets, the report never
  quotes the matched value. Closes the PII gap vs SkillEvaluator's Tier 1.
- **`skill-distinctiveness` check** (skill-only). Flags whole paragraphs of
  guidance repeated verbatim in a SKILL.md — context the model re-reads and the
  buyer re-pays for on every trigger. This is the single-artifact half of
  SkillEvaluator's Tier 2 distinctiveness check. Total checks: 54 → 56.

### Notes

- Negative cases stay in the normal score basis (they are not adversarial
  attacks) but are excluded from the uplift computation, where both arms
  correctly do nothing and the delta is only noise.
- Two SkillEvaluator capabilities are deliberately NOT built into Assay because
  they do not belong in a single-artifact, offline evaluator: **cross-catalog
  dedup** and a **public leaderboard** are properties of the whole catalog and
  belong to the registry; a **multiple-agent-runner matrix** (Claude Code +
  Codex CLIs) is a large separate effort whose marginal signal is small
  (SkillEvaluator's own data: ~5-point harness variance vs +2 to +46 per skill).

## [0.2.4] — 2026-08-13

### Fixed

- **Metadata-endpoint SSRF flag no longer fires on E2B infrastructure.** E2B's
  microVM contacts the cloud metadata endpoint (`169.254.169.254`) as part of
  its own operation, so the runtime ledger raised a spurious SSRF flag on every
  E2B eval. The flag is now suppressed when the sandbox is E2B (where it carries
  no signal about the artifact) and stays fully active on podman, docker, and
  every other sandbox, where a metadata hit really is the code under test.

## [0.2.3] — 2026-08-13

### Fixed

- **Sandbox plumbing no longer reads as an undeclared host.** The runtime
  ledger's declared-vs-observed diff now treats the RFC 5737 TEST-NET ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) as non-routable
  infrastructure, alongside the private and link-local ranges it already
  ignored. E2B routes some internal traffic through `192.0.2.1`, which was
  otherwise flagged as an undeclared host on every E2B run.

## [0.2.2] — 2026-08-13

### Fixed

- **Report provenance names the right version.** `0.2.1` shipped with the
  hard-coded `ASSAY_VERSION` still reading `0.2.0` (the `0.2.1` bump touched
  only `package.json`), so every report it produced was stamped
  `assay/0.2.0`. The constant now matches the package version, and a unit
  test in the normal `npm test` gate asserts they stay in lockstep — a manual
  publish can no longer bypass the check the release workflow already did.

## [0.2.1] — 2026-08-13

Fixes the runtime network ledger on the local (podman) and E2B sandboxes.

### Fixed

- **Network ledger reliably reports again.** `tcpdump -i any` was capturing
  full packet payloads including a provisioning `npm install`'s downloads
  (~60 MB), which blew past the 8 MB retrieval cap, so the whole capture was
  discarded and mislabeled "network capture unavailable." Capture now uses a
  BPF filter for only what the ledger reads (TCP SYNs, DNS, and the TLS
  ClientHello) with a small snaplen, so the pcap stays in the low kilobytes
  even under heavy install traffic. The filter is passed via `tcpdump -F`
  (a file), not a shell argument, because nested quoting had left tcpdump
  running with a filter that compiled but matched zero packets. The retrieval
  cap is raised to 32 MB as a safety net. Verified end-to-end on both podman
  and E2B (the observed host `api.github.com` now appears in the ledger).
- **Honest capture states.** The report now distinguishes "no outbound
  connections observed (capture ran; nothing to report)" from "network
  capture did not complete", naming the actual reason instead of a blanket
  "unavailable."

### Internal

- Regression coverage for the Linux SLL2 link type that `-i any` captures
  actually produce (previously only `RAW_IP` was exercised).
- Dropped an accidental self-dependency from `package.json`.

## [0.2.0] — 2026-08-09

The runtime-ledger + hardened-probes milestone. `0.1.x` graded an artifact from
its source; `0.2.0` also watches what it _does_ when run, verifies MCP servers
against the protocol, and roughly triples both the static check set and the
adversarial probe corpus. Static grading remains zero-dependency and offline;
the new runtime evidence is gathered in a sandbox only when a behavioral run is
requested.

### Added

- **Runtime behavior ledger.** A sandboxed run now records network connections,
  DNS, file access, and spawned commands (pcap + strace) and diffs _declared_
  against _observed_ behavior, so an artifact that reaches an undeclared host or
  touches a sensitive file is surfaced as evidence, not opinion. Works on podman
  as well as Docker; the packet ledger understands IPv6.
- **MCP protocol depth.** The harness captures the full MCP protocol surface
  (not just `tools/list`), emits a protocol-conformance verdict, and runs a
  tool-annotation truth-check — a tool annotated read-only that in fact
  writes/persists is caught (`save`/`store`/`persist`/`append`/`log` count as
  state-changing). `tools/list` is paginated, and servers are driven over
  **Streamable HTTP** as well as stdio.
- **MCP auth-posture check** and an **injection-resistance grade** for
  MCP/agent artifacts.
- **Static coverage expanded to 54 checks** (from 45), adding: MCP resources,
  prompts, and concealed-metadata surfaces; a skill safety & cost bundle
  (hostile actions, token footprint, resource refs, spec conformance); agent
  system-prompt hostile-instruction scan + tool-scope blast-radius; plugin hook
  indirection following, a pre-trust/privilege-abuse hook classifier, and safety
  recursion into bundled components.
- **Adversarial probe corpus grown 12 → 44**, with agent and plugin corpora
  brought to parity with MCP.
- **Skill uplift-vs-baseline:** does the skill actually beat the bare model?
- **Suite presets made real** via `--suite` — `recommended`, `strict`, and
  `mcp-server`.
- **Declarative check + probe authoring** through a `plugins: []` config, so
  callers can extend the suite without patching the engine.
- **GitHub Action** for CI, with deduplicated SARIF rule tags.
- **Reporting/provenance:** reports record provenance, the synthesis model, and
  token spend; a confidence interval is attached to the behavior axis; the
  strongest available driver is the default; `explain --json` is implemented.

### Changed

- The behavioral harness now **enforces** the declared tool scope during a run
  rather than only recording it.
- Ledger dedup and capture-noise cleanup for quieter, more deterministic output.

### Notes

- Prior release: `0.1.11`. `0.2.0` is the next public minor; the internal
  "0.2"/"0.5" milestone codenames used during development are not version
  numbers. The project remains well short of the `1.0` maturity milestone.

[0.2.6]: https://github.com/metahub-ai/assay/releases/tag/v0.2.6
[0.2.5]: https://github.com/metahub-ai/assay/releases/tag/v0.2.5
[0.2.4]: https://github.com/metahub-ai/assay/releases/tag/v0.2.4
[0.2.3]: https://github.com/metahub-ai/assay/releases/tag/v0.2.3
[0.2.2]: https://github.com/metahub-ai/assay/releases/tag/v0.2.2
[0.2.1]: https://github.com/metahub-ai/assay/releases/tag/v0.2.1
[0.2.0]: https://github.com/metahub-ai/assay/releases/tag/v0.2.0
