# Security Policy

## Reporting a vulnerability

Please report security issues privately via
[GitHub Security Advisories](https://github.com/metahub-ai/assay/security/advisories/new)
rather than a public issue.

Include what you were doing, what happened, and — if you have one — a minimal
reproduction. You will get an acknowledgement within 3 business days and an
assessment within 10.

## Assay's own threat model

Assay evaluates untrusted artifacts, which makes it a target in two distinct
ways. Both are in scope.

### 1. A malicious artifact attacking the evaluator

Assay reads artifacts written by strangers, and behavioral evaluation _executes_
them.

- **Path containment.** `DirectorySource` refuses to read outside the artifact
  root. Containment is checked against the **realpath**, not just lexically —
  an earlier version checked only the literal path, and because `resolve()` does
  not follow symlinks while `readFile()` does, a symlink committed inside an
  artifact (`escape-link -> /etc/passwd`) escaped the root. That is a regression
  test now.
- **Sandbox isolation.** Behavioral runs happen inside a sandbox provider
  (podman locally, E2B in the cloud) with a wall-clock ceiling, never in the
  host process.
- **Never `eval`.** Assay does not evaluate artifact code in-process. This is
  worth stating because several well-known eval frameworks do — HELM's source
  says outright _"This function is NOT a security sandbox."_

### 2. A malicious _check_ attacking the host

Third-party checks are ordinary code from strangers, so they are
capability-scoped:

```ts
export type Capability = "net" | "llm" | "sandbox" | "clock";
```

A check receives exactly what it declared and nothing else. An undeclared
capability is `undefined` at runtime, not merely against the rules. A check
declaring `determinism: "deterministic"` may declare **no** capabilities, and
violating that is a load error.

This is enforcement, not etiquette — it is what makes the reproducibility tier
mechanically true rather than a promise in a comment.

### Known limits

Stated plainly, because a threat model that only lists wins is marketing:

- **Capability scoping is not a JS sandbox.** A malicious check running in the
  same process could still reach Node built-ins directly. Treat third-party
  checks as you would any dependency: review them, or run Assay itself in a
  container.
- **Dynamic analysis observes only the paths it triggers.** Sandbox-evasive,
  time-delayed, and remotely-fetched payloads will look clean.
- **Assay is not a malware scanner.** It reports observed behavior and specific
  findings; it does not claim to catch everything, and a passing report is not a
  safety guarantee.

## Supported versions

Pre-1.0: only the latest minor receives fixes.
