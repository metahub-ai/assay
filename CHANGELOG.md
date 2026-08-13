# Changelog

All notable changes to `@metahub-ai/assay` are documented here. This project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html); while on
`0.x`, minor versions may carry breaking changes.

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
its source; `0.2.0` also watches what it *does* when run, verifies MCP servers
against the protocol, and roughly triples both the static check set and the
adversarial probe corpus. Static grading remains zero-dependency and offline;
the new runtime evidence is gathered in a sandbox only when a behavioral run is
requested.

### Added

- **Runtime behavior ledger.** A sandboxed run now records network connections,
  DNS, file access, and spawned commands (pcap + strace) and diffs *declared*
  against *observed* behavior, so an artifact that reaches an undeclared host or
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

[0.2.2]: https://github.com/metahub-ai/assay/releases/tag/v0.2.2
[0.2.1]: https://github.com/metahub-ai/assay/releases/tag/v0.2.1
[0.2.0]: https://github.com/metahub-ai/assay/releases/tag/v0.2.0
