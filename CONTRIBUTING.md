# Contributing to Assay

Thanks for considering it. This document is mostly about **the bar a check has
to clear**, because that is where Assay's credibility lives or dies.

## The short version

- A check must be **automatable and objective** — no human judgement in the loop.
- A check must produce **evidence**, not just a verdict.
- A check must be **actionable**: a publisher reading it must know what to change.
- A check must be **testable offline**, from a plain object literal.
- Anything that could change a published verdict needs a **version bump** and an
  explanation in the release notes. A score is a claim about somebody else's
  work: if an artifact scored 88 last month and 71 today, its author is owed an
  answer to "what changed, you or me?"

### One rule above the others

**A false positive is worse than a false negative.** A verdict is a public claim
about somebody else's work. A check that misses something costs us; a check that
is wrong about a correct artifact costs _them_, and they cannot appeal it.

This is not hypothetical here. Checks in this repo have, at various points:
demanded a `README.md` and failed all ten official Anthropic skills; warned at
`allowed-tools: []`, which is exactly what the check's own remediation asks for;
failed a _blocking_ check on a `.env` that was gitignored and then advised
gitignoring it; scored a correct skill below a lorem-ipsum stub for using an
ordinary YAML folded scalar; and matched shell patterns against file contents,
so a skill writing documentation that mentioned `rm -rf` was recorded as unsafe.

Every one of those shipped with tests. What the tests lacked was a case built
from something real and correct. So: **for every check, write the test that
proves it does not fire on a legitimate artifact.** Half the tests in
`tests/content.test.ts` are that shape, deliberately.

## Development

```bash
npm install
npm test              # ~830 tests, runs in ~2s
npm run typecheck
npm run test:coverage
```

There is no Docker requirement, no API key, and no network access needed for the
default suite. If your change breaks that, it is very likely the wrong shape —
see [Testing](#testing).

## Writing a check

```ts
import { defineCheck } from "assay";

export default defineCheck({
  id: "acme/no-eval", // kebab-case; namespace third-party ids
  version: "1.0.0", // semver of the LOGIC
  title: "No dynamic eval", // shown in UIs
  category: "safety", // free-form string
  axis: "safety", // integrity | safety | care | behavior
  determinism: "deterministic",
  weight: 3, // 0 = informational: reported, never scored
  blocking: false, // does a `fail` stop a publish?
  spec: "https://acme.dev/checks/no-eval",
  async run(ctx) {
    /* ... */
  },
});
```

### Choosing a determinism tier

| Tier            | Use when                                               | May declare      |
| --------------- | ------------------------------------------------------ | ---------------- |
| `deterministic` | The verdict is a pure function of the artifact bytes   | **nothing**      |
| `replayable`    | You drive a model or sandbox and record the transcript | `llm`, `sandbox` |
| `sampled`       | The verdict legitimately varies run to run             | any              |

`deterministic` + any capability is a load error, not a lint warning. If your
check reads the clock, it is not deterministic — recency changes verdict with no
change to the artifact, which is why `clock` is a capability at all.

### Choosing a status

| Status                   | Means                                                  | Counted?                         |
| ------------------------ | ------------------------------------------------------ | -------------------------------- |
| `pass` / `warn` / `fail` | A judgement about the subject                          | Yes                              |
| `neutral`                | Genuinely does not apply, and that is not a deficiency | No, and does not reduce coverage |
| `skip`                   | We did not look                                        | No, **reduces coverage**         |
| `error`                  | **We** failed, not the artifact                        | No, **reduces coverage**         |

The distinction between `skip`/`error` and `pass` is the one that matters most.
A check that cannot do its job must **never** return `pass`. There is a
regression test for this, because an early version of `deps-no-known-vulns`
returned `pass` with a summary claiming it had scanned dependencies it never
looked at — a clean bill of health backed by fabricated evidence. `skip` costs
visible axis coverage, and that self-punishing cost is the point.

### Evidence is required

A finding without evidence is a complaint. Every `fail` and `warn` should carry
at least one of:

```ts
{ type: "file", path: "src/index.js", line: 42, excerpt: "..." }
{ type: "url", url: "https://api.osv.dev/...", sha256: "..." }
{ type: "transcript", sha256: "...", uri: "...", turns: 12 }
{ type: "metric", name: "days_since_last_commit", value: 42, unit: "days" }
```

**Never put a secret in evidence.** `no-sensitive-files` reports the _path_ of a
leaked credential file and never its contents — a report that quotes the secret
has republished it. There is a test asserting this.

### What makes a bad check

Learn from the field's mistakes rather than repeating them:

- **File-presence points.** Libraries.io's SourceRank awarded nine points for
  having a README, a LICENSE, a description, and a `v1.0.0` tag. It published
  its whole formula and is still dismissed, because transparency without
  cost-to-fake is a cheat sheet. Prefer signals that are expensive to fake.
- **Recency as quality.** SourceRank did it in 2016; OpenSSF Scorecard's
  `Maintained` still requires roughly a commit a week. Both reward churn and
  punish completion — a small, correct, finished library decays toward a bad
  grade forever. Assay's own `recently-maintained` is **weight 0** for exactly
  this reason: it reports, it never scores.
- **Popularity.** Stars have a counterfeit market; a 2024 study identified ~4.5M
  suspected fake stars whose largest single use was promoting malware. And
  popularity was excellent for `event-stream`, `colors`, and `node-ipc` the day
  before each went malicious. Assay does not take popularity as an input.

## Testing

Every check must be testable from an in-memory literal:

```ts
import { MemorySource } from "assay";

const ctx = { source: new MemorySource({ "index.js": "eval('x')" }) /* ... */ };
expect((await check.run(ctx)).status).toBe("fail");
```

If a check can only be exercised against a live repo, a cloud sandbox, and a
paid model, it is coupled to a transport — and a framework nobody can run in CI
is a framework nobody can audit or contribute to.

Coverage thresholds are enforced (`statements`/`functions`/`lines` at 85,
`branches` at 75). The lower branch bar is deliberate and explained inline in
`vitest.config.ts`; vendor adapters are excluded and that exclusion is recorded
in [docs/COVERAGE.md](docs/COVERAGE.md). **Do not add a silent exclusion** —
hidden exclusions are how coverage numbers start lying.

## Versioning and published verdicts

Assay makes claims that people may act on, so changing one has rules:

- **Bump `version` whenever a verdict could change on unchanged input.** This is
  the signal downstream caches and diffs key on.
- **A substantive change in what a check MEANS mints a NEW id.** `checkVersion`
  covers refinement; it must not be used to quietly redefine a verdict. Retired
  ids are never reused.
- **New checks land as informational first** (`weight: 0`) where practical, so
  publishers can satisfy them before they bite.
- Anything that moves scores gets the `score-affecting` label, and the release
  notes say plainly what moved, why, and who is affected — with before/after
  numbers on real fixtures where possible.

## Pull requests

1. Fork, branch, and keep the change focused.
2. `npm test && npm run typecheck && npm run format:check` must pass.
3. Explain **why**, not just what. A check's rationale is part of its
   specification — if you cannot articulate the risk it detects, it probably
   should not gate anyone's publish.
4. If it changes a verdict, say so explicitly in the PR description.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

By contributing you agree your contributions are licensed under
[Apache-2.0](LICENSE).
