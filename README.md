<div align="center">

# Assay

**An open, reproducible framework for evaluating AI artifacts**<br>
skills · MCP servers · agents · plugins

[![CI](https://github.com/metahub-ai/assay/actions/workflows/ci.yml/badge.svg)](https://github.com/metahub-ai/assay/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A520-brightgreen.svg)](package.json)

</div>

---

Every registry that distributes AI artifacts answers _"where did this come
from?"_ None answers _"what does it actually do?"_ as a published, auditable
signal.

Assay answers the second question. It reads what is inside an artifact, and
optionally **runs it** in a sandbox with a real model and judges what it did —
then publishes a report that somebody who does not trust you can check.

```bash
curl -fsSL https://raw.githubusercontent.com/metahub-ai/assay/main/install.sh | sh
assay run anthropics/skills//skills/pdf
```

---

## Contents

- [Why](#why) · [Install](#install) · [Quickstart](#quickstart)
- [What you point it at](#what-you-point-it-at) · [Reading the output](#reading-the-output)
- [Running the artifact](#running-the-artifact) · [In CI](#in-ci) · [Signing and verifying](#signing-and-verifying)
- [How it works](#how-it-works) · [Writing a check](#writing-a-check) · [Library use](#library-use)
- [What Assay does not claim](#what-assay-does-not-claim)

---

## Why

The gap is not an oversight. The official MCP Registry
[states in writing](https://modelcontextprotocol.io/registry/moderation-policy)
that consumers should "assume minimal-to-no moderation," and that it will not
remove "low-quality or buggy servers" or "servers with security
vulnerabilities." It relies instead on "upstream package registries (like NPM,
PyPI, and Docker) or downstream subregistries."

Meanwhile every trust layer the industry does rely on has a dated
counterexample.

**Provenance** — `postmark-mcp` shipped 15 clean versions, then v1.0.16 added
one line BCC'ing every email to an attacker. 1,643 downloads before removal.
<sub>[Koi Security](https://www.koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft) ·
[The Hacker News](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html) ·
[Postmark's advisory](https://postmarkapp.com/blog/information-regarding-malicious-postmark-mcp-package)</sub>

**Reputation** — the SmartLoader campaign built five fake GitHub accounts
cross-forking each other to manufacture a community around a trojanized Oura
MCP server. It later expanded to 7,600 repositories, roughly 800 posing as
Skills or MCP servers.
<sub>[The Hacker News](https://thehackernews.com/2026/02/smartloader-attack-uses-trojanized-oura.html) ·
[Straiker](https://www.straiker.ai/blog/smartloader-clones-oura-ring-mcp-to-deploy-supply-chain-attack) ·
[FakeGit campaign](https://thehackernews.com/2026/07/fakegit-campaign-uses-7600-github.html)</sub>

**Static analysis** — Self-Extracting Skill packing bypassed **every one of nine**
scanners tested at ≥90%, reaching 99.8% on five of six static scanners.
<sub>["Cloak and Detonate"](https://arxiv.org/html/2607.02357), arXiv:2607.02357 — the technique is
SFS Packing, part of SkillCloak · Koi Security's
[ClawHavoc](https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting)
found 341 malicious skills on one marketplace</sub>

**Model alignment** — MCPTox measured attack success up to 72.8% and
best-in-class refusal under 3%, and found that _more capable models were more
susceptible_.
<sub>["MCPTox"](https://arxiv.org/abs/2508.14925), arXiv:2508.14925, published at AAAI —
45 live MCP servers, 353 real tools, 1,348 malicious test cases</sub>

The premise is that the missing signal is **observed behavior**, and that such a
signal is worth nothing unless outsiders can check it.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/metahub-ai/assay/main/install.sh | sh
```

No domain, no package registry, no sudo. It pulls a release tarball from GitHub
Releases, checks it against the `sha256` published beside it, and unpacks into
`~/.assay`. Read it first if you like — pipe it to `less` instead of `sh`.

That works because **the tool has no runtime dependencies**: a ~240 KB tarball
of self-contained JavaScript. Every model adapter speaks its vendor's HTTP API
directly, so a fresh install can run the behavioral tier with nothing more than
a key — there is no SDK to add afterwards. `e2b` and `sigstore` remain optional
peers, imported lazily and only if you use the E2B sandbox or keyless signing.

<details>
<summary>Other ways to install</summary>

```bash
# straight from the repo, no registry publish involved
npx github:metahub-ai/assay run .

# a specific release
curl -fsSL .../install.sh | sh -s -- --version=v0.1.2

# from source
git clone https://github.com/metahub-ai/assay.git
cd assay && npm ci && npm run build && npm link
```

Node 20+ in every case. Uninstall is `rm -rf ~/.assay`.

</details>

## Quickstart

```bash
assay run .
```

No configuration, no account, no API key. Offline, about a second.

```bash
assay doctor      # what can I run right now?
assay list        # the 43 checks, grouped by axis
```

## What you point it at

You do not have to clone first. Every line below is a real, public artifact:

```bash
assay run .                                                  # a local directory
assay run ~/.claude/skills/canvas-design                     # something installed
assay run anthropics/skills//skills/pdf                      # a subdirectory of a repo
assay run anthropics/skills//skills/pdf#main                 # pinned to a tag or commit
assay run https://github.com/anthropics/skills/tree/main/skills/docx
assay run npm:@modelcontextprotocol/server-memory            # integrity-checked
assay run modelcontextprotocol/servers//src/fetch            # a Python MCP server
assay run metahub:skill/warden                               # from the registry
```

### From a registry

```bash
assay run metahub:skill/warden      # or metahub:warden to discover the kind
```

```
  Resolving metahub:skill/warden
  skill warden v0.1.0 pinned to c79f4eb9b7b9
  Fetching commit c79f4eb9b7b9
```

A registry does not host artifact bytes — it holds a catalog entry naming
where they are and **which commit it is serving**. That last part is the
reason to resolve through it: `assay run owner/repo//path` grades whatever
`main` is at the moment you ask, which is not what anybody installed.
`metahub:` pins the evaluation to the commit a consumer actually receives,
so **the grade and the install cannot drift apart**. The registry is also
authoritative about the artifact's kind, so detection stops being a guess.

Set `ASSAY_REGISTRY` for a self-hosted deployment; `registry:` works as a
vendor-neutral alias. Private and unlisted artifacts are not reachable, and
the resolver says so rather than reporting them as missing.

A GitHub `/tree/` URL is the one people actually have in their clipboard, so the
ref and the subdirectory are read straight out of it.

<details>
<summary>Why the double slash, and two other conventions</summary>

**`//` separates the repository from a path inside it.** A single slash cannot,
because a git server may legitimately host a repository at `/network.git/a`.
This is why Terraform chose `//`, and why degit ended up brute-forcing every
possible split point once nested GitLab namespaces existed.
`owner/repo/skills/pdf` is rejected with both corrections rather than guessed at.

**`#` marks a ref** (`@` is accepted too). It is the URL fragment, so it composes
with full URLs and never collides with SSH's `user@host`. npm, npx, degit and
Yarn all do this.

**An existing local directory always wins.** `src/utils` is both a valid GitHub
shorthand and a plausible folder. Silently cloning a stranger's repository when
someone meant a local path is much the worse failure, so the disk wins; use
`gh:owner/repo` to force the remote.

</details>

Remote targets are fetched into a temporary directory that is removed when the
run ends, and the report records the **resolved commit**, not the branch you
asked for — a grade over "whatever `main` was that day" is not reproducible.
npm packages are checked against the registry's own integrity hash, and are
never fetched with `npm pack`, which can execute `prepare` scripts from the
package you are trying to audit.

## Reading the output

```
  pdf  skill
  1cbcfa643929c208…  ·  b29e7cf65e5cb78a5ac33d582270551bc74a14eb

  ────────────────────────────────────────────────────────────────────

  OVERALL   ████████████████████  98.1/100   PASS
            19 of 21 checks judged  ·  2 skipped  ·  9 n/a  ·  behavior not measured

  integrity ████████████████████    100   100% measured
  safety    ████████████████████   97.6    91% measured
  care      ███████████████████░   95.8   100% measured
  behavior  ····················      —     not measured

  Nothing here ran the artifact. `assay setup` configures a sandbox
  and a model once, after which behavioral evaluation is part of a
  plain `assay run` — see `assay doctor`.

  scoring   assay-default@1.0.0

  ────────────────────────────────────────────────────────────────────

  WORTH A LOOK

    ▲ Tool scope declared
      No tool scope declared.
      Without `allowed-tools` the skill inherits whatever the client
      grants — the broadest possible scope, and nothing on the listing
      tells a consumer that.
      SKILL.md:1
      → Declare `allowed-tools` with the minimum set the skill actually
        needs. If it needs none, declare an empty list explicitly.
```

The two lines under the name are the content digest and the resolved commit.
Failures come before warnings, warnings before passes, and evidence prints as
`path:line` because that is what terminals and editors turn into a jump.

**Coverage is printed beside every axis and is never hidden.** An axis nothing
measured renders as a dash and the words _not measured_ — never as a zero the
artifact appears to have earned. Below a global floor there is no headline
number at all:

```
  OVERALL   not enough was measured to publish a score
  Too many checks were skipped for an aggregate to mean anything.
  Granting more capability (--net, --behavioral) raises coverage.
```

Colour disappears under `NO_COLOR`, when stdout is not a terminal, and for
`TERM=dumb`. Progress goes to stderr, so `--json` piped into `jq` stays clean.
`ASSAY_ASCII=1` swaps box-drawing and glyphs for ASCII.

Exit codes: `0` no blocking failure · `1` a blocking check failed or the score
is below `--min-score` · `2` the run could not complete.

Until `assay setup` has run, `assay run` is **offline by default** — it grants
no network, model, or sandbox access — so it is safe to point at code you have
not read. Checks needing those capabilities report reduced coverage rather than
being silently dropped.

## Running the artifact

Everything above is static. This is the part that runs the artifact and judges
what it does. It costs money and time — roughly a few cents per artifact with a
small judge model, and anywhere from fifteen seconds to two minutes.

```bash
assay setup     # pick a sandbox and a model, once
assay run ~/.claude/skills/canvas-design --transcripts ./transcripts
```

**Configuring it is the opt-in.** Once `setup` has chosen a sandbox and a model,
behavioral evaluation is part of a plain `assay run` — you do not have to ask
for it again. Two exceptions, both deliberate:

- **No terminal, no default.** In CI, a pipe, or anything without a TTY it stays
  opt-in and you pass `--behavioral`. A pipeline that inherited credentials
  because somebody set them once must not silently start billing per commit and
  adding minutes to every build.
- **A blocking safety failure vetoes it.** Assay will not execute an artifact
  its own static checks have just flagged as malicious. `--behavioral` overrides
  that — the sandbox is what the sandbox is for — but it has to be asked for.

`--no-behavioral` skips it however the machine is configured, and `assay setup`
records the answer if you would rather it were off by default. `assay doctor`
reports which of these applies here.

`setup` verifies the key against the provider **before saving it**, tells you
where it went (`~/.assay/config.json`, mode 0600), and warns when an environment
variable already shadows it. Environment variables always win: CI sets secrets
that way, and a stale file silently overriding a rotated CI secret is a failure
that takes a day to find.

<details>
<summary>How the behavioral tier works</summary>

A **driver model** is given the artifact's documentation as its system prompt
and a set of test cases — read from `evals/*.json` if the author shipped them,
otherwise synthesized from the docs. It drives the artifact inside a container
with real tool calls. Every transcript is then scored by a **separate judge
model** against a rubric, and a **deterministic safety scan** runs over the
captured commands regardless of what the judge said — a model that overlooks an
`rm -rf` cannot bless it.

Three adversarial probes are layered on by default (prompt injection,
scope-creep, a destructive request). They are scored separately and excluded
from the headline: refusing them is the pass, and a probe's dimension scores are
undefined when the artifact behaves correctly.

`--sandbox podman` is local and free. `--sandbox e2b` runs it in the cloud and
needs `E2B_API_KEY`. The framework never executes artifact code in-process, and
the report records which sandbox and which model produced the grade.

Model keys come from `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
`OPENROUTER_API_KEY`, or `LOCAL_LLM_BASE_URL` for Ollama/vLLM/LM Studio. If
several are set, Assay refuses to choose and asks for `--provider` — picking
silently would make a published grade depend on ambient state.

</details>

The driver is a model, so one sample per case is noisy. `--repeat k` runs each
case `k` times and reports a confidence interval alongside the score.

### Replaying a verdict

Given a report and the transcripts it recorded, re-judge them and see whether
the verdicts hold:

```bash
assay replay report.json --transcripts ./transcripts
```

```
  replaying 5 transcript(s) with openrouter

    ✔ b322abb3d479…  fail → fail
    ✔ dcb07f36e747…  fail → fail

  All verdicts reproduced.
```

Exits 1 on disagreement, so it works as a scheduled check. Replay verifies the
**grade, not the run** — "given this transcript, was the judgement fair?" It
does not re-execute the artifact, which is a different and far more expensive
dispute. Settling the cheap one offline is most of the value.

## In CI

```bash
assay run . --sarif > assay.sarif      # GitHub code scanning ingests this
assay run . --min-score 80             # exits 1 below the threshold
assay diff base.json head.json         # exits 1 only on a REGRESSION
```

`diff` is the one CI usually wants. "How good is this?" forces every project to
pick an absolute threshold on day one; "did this change make it worse?" does
not. When the subject digest is unchanged it says so explicitly — any delta then
came from Assay, not from the author.

```
  regressions
    no-escaping-symlinks         neutral → fail

  score     -51.4
  1 regression(s), 0 surface change(s) needing review.
```

It also fails on a check that **stopped judging** — the quiet failure that
otherwise sails straight through the gate.

### Catching a rug pull

An artifact that earns trust and then changes what it does is the attack
provenance cannot catch, because the provenance is genuine. Assay records the
tool surface on every run — offline, no sandbox needed — and `diff` compares it.
A behavioral run additionally captures what `tools/list` actually returned, so a
server that ships one description and _returns_ another is visible too. Assay
refuses to diff a declared surface against an observed one, because they are
different measurements and comparing them would emit false alerts people learn
to ignore.

### Waivers

Every check will eventually be wrong about somebody. Without a way to say
"deliberate, here's why," the only options are a permanent red mark or turning
the tool off — and people pick the second, at which point it protects nobody.

```json
{
  "waivers": [
    {
      "check": "no-install-scripts",
      "reason": "Native module needs node-gyp at install; reviewed 2026-08-01.",
      "expires": "2027-01-01",
      "paths": ["scripts/**"]
    }
  ],
  "settings": { "docsMinWords": 80 },
  "minScore": 70
}
```

Designed to be _expensive to abuse_ rather than merely available: the reason is
mandatory and published in the report, the finding becomes `neutral` with the
reason attached rather than disappearing, an expiry actually expires, and
`paths` is enforced — a finding reaching outside the scope stands, and the
report names the files the waiver did not cover.

## Signing and verifying

```bash
assay keygen --out mykey
assay run ./my-skill --json > report.json
assay sign report.json --key mykey.pem --pub mykey.pub.pem
assay verify report.json --key mykey.pub.pem --artifact ./my-skill
```

```
  ✔ score      Score recomputes from the results.
  ✔ subject    Subject digest matches the artifact provided.
  ✔ signature  Signature valid (keyid 86e38a2884a5ed01).

  Report verified.
```

Three independent questions, three independent answers. The middle one is the
interesting one: **it holds even against someone holding the signing key.**
Re-signing an altered report produces a valid signature over an inconsistent
document, and recomputing the score from the findings catches it anyway.

Without `--key`, a valid signature only proves _somebody_ signed, so that case
is reported as an open question rather than a pass. `--require-signature` makes
an unsigned report a failure.

<details>
<summary>Keyless signing via Sigstore</summary>

```bash
assay sign report.json --keyless
```

An ephemeral key is generated, an OIDC identity proves who is running, Fulcio
issues a ~10-minute certificate, the signature goes into Rekor's public
transparency log, and the private key is discarded. There is nothing left to
steal, and issuance is publicly auditable rather than asserted — which matters
for a party publishing verdicts about other people's work.

Verification requires an expected identity:

```bash
assay verify report.json --bundle report.sigstore.json \
  --issuer https://token.actions.githubusercontent.com \
  --identity "https://github.com/me/repo/.github/workflows/release.yml@refs/heads/main"
```

Needs an OIDC identity — ambient in CI with `id-token: write`, a browser flow
locally. The local ed25519 path above still works entirely offline.

</details>

### Known-vulnerable dependencies

```bash
assay run . --net        # allows api.osv.dev only. No model, no cost.
```

OSV rather than NVD, deliberately: NVD describes affected software with CPE
strings, a taxonomy invented for enterprise inventory with no canonical mapping
to an npm or PyPI name. `--net` grants **only** the advisory lookup, through an
allowlisted client that refuses plaintext, re-checks the allowlist on every
redirect hop, and records every request into the report.

## How it works

### Determinism is enforced, not asserted

Every check declares a tier, and the tier is **mechanically true** because
capabilities are granted by declaration. A `deterministic` check that requests a
capability **fails to load** — not a convention, a `throw`.

| Tier            | Promise                                                                                            |
| --------------- | -------------------------------------------------------------------------------------------------- |
| `deterministic` | Pure function of the artifact bytes and the check version. Re-running in 2030 is byte-identical.   |
| `replayable`    | Expensive to produce, cheap to verify. The transcript is recorded, so the grade can be re-derived. |
| `sampled`       | Irreducibly stochastic. Must report `n`, mean, spread, and `pass^k`.                               |

Seeding is _not_ the reproducibility story. Nondeterminism at temperature 0
comes from a lack of batch invariance in GPU kernels: many kernels produce
different numerics depending on the batch they land in, so a request's output
depends on what else was in the forward pass at that moment. Sampling one
prompt 1,000 times at temperature 0 produced 80 distinct completions.
It is fixable — with batch-invariant kernels, in your own serving stack — but
not by anyone calling a hosted API, which is what an evaluator is doing.
Recording and replaying is.

### Judgements carry their evidence

A finding that says "found a hardcoded secret" without saying **where** is
unfalsifiable and unfixable. Every result carries `Evidence` — a file path and
line, an external URL with a response digest, a transcript digest, or a
structured metric. Secret findings deliberately report the path and never the
matched text, because a report that quotes the credential has republished it.

### Four axes, not one number

| Axis        | Question                                      |
| ----------- | --------------------------------------------- |
| `integrity` | Is it well-formed and does it load?           |
| `safety`    | Could installing this hurt me?                |
| `care`      | Is it maintained by someone paying attention? |
| `behavior`  | Does it actually do what it claims?           |

Four rules, each executable as a test:

1. **Coverage is reported, never assumed.** An axis that could not be measured
   says so, in the human output and as `null` in the JSON.
2. **`error` never counts against the subject.** Our sandbox timing out is our
   problem, not a mark on someone's work.
3. **Safety does not average.** A blocking safety failure _floors_ the axis —
   credential exfiltration is not offset by a tidy README.
4. **The formula is versioned and published**, and the whole computation runs
   off the report, so anyone can recompute the number or show that they can't.

The field has been moving away from composite scores. OpenSSF Scorecard's own
v6 roadmap reframes the project around producing "trusted, structured security
evidence," with per-probe results that consumers can act on instead of an
aggregate out of ten. And a peer-reviewed study of 679 projects found reported
vulnerabilities _increased_ as the aggregate Scorecard score increased.

<sub>[Scorecard v6 roadmap](https://github.com/ossf/scorecard/pull/4952) ·
[Beyond Scores with OpenSSF Scorecard](https://openssf.org/blog/2024/04/17/beyond-scores-with-openssf-scorecard-granular-structured-results-for-custom-policy-enforcement/) ·
["Do Software Security Practices Yield Fewer Vulnerabilities?"](https://arxiv.org/html/2210.14884), arXiv:2210.14884</sub>

That is why the headline sits behind a coverage floor, why the four axes are
reported alongside it, and why `--json` is the surface a consumer is expected to
build on.

## Writing a check

A check is a standalone, versioned module. That is the whole point — it turns
"trust our score" into "read the check that produced it."

```ts
import { defineCheck } from "@metahub-ai/assay";

export default defineCheck({
  id: "acme/no-eval",
  version: "1.0.0",
  title: "No dynamic eval",
  category: "safety",
  axis: "safety",
  determinism: "deterministic",
  weight: 3,
  async run(ctx) {
    const src = (await ctx.source.readFile("index.js")) ?? "";
    const line = src.split("\n").findIndex((l) => l.includes("eval("));
    if (line < 0) return { status: "pass", summary: "No eval() calls." };
    return {
      status: "fail",
      summary: "Uses eval().",
      evidence: [{ type: "file", path: "index.js", line: line + 1 }],
      remediation: "Replace eval() with an explicit dispatch table.",
    };
  },
});
```

Namespace third-party ids as `vendor/check-name`. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the bar a check has to clear.

Every check in the default suite is documented in
[docs/CHECKS.md](docs/CHECKS.md), generated from the registry so it cannot drift
from the code. `assay explain <check-id>` prints the same thing in your
terminal, including the waiver snippet.

## Library use

```ts
import {
  runAssay,
  CheckRegistry,
  CORE_CHECKS,
  DirectorySource,
  digestTree,
} from "@metahub-ai/assay";

const source = new DirectorySource("./my-skill");
const report = await runAssay({
  subject: {
    kind: "skill",
    name: "my-skill",
    source: { type: "directory", path: "./my-skill" },
    digest: { sha256: await digestTree(source) },
  },
  source,
  registry: CheckRegistry.from(CORE_CHECKS),
  suite: { id: "assay-starter", version: "0.1.0" },
  environment: { runner: "assay/0.1.0" },
});
```

Sandbox adapters ship for **podman** (local, default) and **E2B** (cloud). Model
adapters ship for **Anthropic**, **OpenAI**, **OpenRouter**, and any
OpenAI-compatible local endpoint; each speaks its vendor's HTTP API directly and
needs no SDK installed. The core framework depends on no vendor.

## What Assay does not claim

Stated up front, because overclaiming is the fastest way to lose the credibility
this project exists to build:

- **Dynamic analysis only observes paths it triggers.** Code on an untaken
  branch is unobserved.
- **Sandbox-evasive and time-delayed payloads defeat it.** This is the standing
  limit of the technique, not a bug we can close.
- **Models detect evaluation.** Anthropic reported (February 2026) that Claude
  Opus 4.6 independently inferred it was being benchmarked, identified which
  benchmark, and located the answer key — and that suppressing its
  eval-awareness increased misaligned behavior, meaning models behave _better_
  when they believe they are being watched. That is an unresolved validity
  problem for every behavioral number, including these.
  <sub>[Eval awareness in Claude Opus 4.6](https://www.anthropic.com/engineering/eval-awareness-browsecomp) ·
  [Claude Opus 4.6 system card](https://www-cdn.anthropic.com/0dd865075ad3132672ee0ab40b05a53f14cf5288.pdf)</sub>

- **The judge is consistent, not validated.** Replayed transcripts reproduce
  their verdicts. Nothing yet measures those verdicts against human labels.
- **The lethal trifecta is not a property of any artifact.** Private data +
  untrusted content + external communication is a property of the _user's whole
  tool graph_. Every individual artifact can pass and the combination still be
  unsafe.

[docs/COVERAGE.md](docs/COVERAGE.md) is the full accounting, including the parts
that are weaker than you would like.

## Documentation

| Document                             | What's in it                                                          |
| ------------------------------------ | --------------------------------------------------------------------- |
| [docs/COVERAGE.md](docs/COVERAGE.md) | What Assay measures, what it doesn't, and what it structurally cannot |
| [docs/CHECKS.md](docs/CHECKS.md)     | Every check in the default suite, generated from the registry         |
| [CONTRIBUTING.md](CONTRIBUTING.md)   | How to write a check, the review bar, the versioning rules            |
| [SECURITY.md](SECURITY.md)           | Reporting a vulnerability, and Assay's own threat model               |

## Development

```bash
npm install
npm test          # 1007 tests
npm run typecheck
npm run lint
npm run build
```

Every core check is testable from a plain object literal via `MemorySource`, and
all four behavioral harnesses run offline against in-memory doubles. If a
contribution can only be exercised against a live cloud sandbox and a paid
model, it is coupled to a transport and the design has failed.

## License

[Apache-2.0](LICENSE) — chosen over MIT for the explicit patent grant, which an
open standard benefits from.
