# Assay — coverage and gaps

**As of 2026-08-02 · assay 0.1.0 · suite `assay-default`**

This document exists because the single highest-credibility artifact found
anywhere in the competitive research was OpenSSF Scorecard's own published
admission that it can fully automate **8 of 59** controls in a minimal baseline.
A project that publishes "we cover 14%" is one you can believe about the other
14%.

So: here is what Assay measures, what it does not, and what it structurally
cannot.

---

## 1. Headline numbers

|                                          | Count                        |
| ---------------------------------------- | ---------------------------- |
| Checks in the default suite              | **35** static + 1 behavioral |
| Checks producing a scored verdict        | **32**                       |
| Checks that are informational (weight 0) | 3                            |
| Checks that are blocking                 | **10**                       |
| Score axes with working coverage         | **4 of 4**                   |
| Tests                                    | **832**                      |

Statement coverage 86.1% · functions 89.9% · lines 87.5% · branches 75.1%.
Measured, not asserted — reproduce with `npm run test:coverage`.

Two modules sit below the 85% threshold and are named rather than averaged away:

| Module     | Statements | Why                                                                      |
| ---------- | ---------- | ------------------------------------------------------------------------ |
| `setup.ts` | ~37%       | The wizard's question sequence needs a terminal                          |
| `cli.ts`   | ~75%       | Command dispatch; the individual commands are covered, the wiring is not |

What _is_ unit-tested in `setup.ts` is everything with a decidable right answer:
credential verification (a 401 blocks, a 503 does not — a vendor outage is not
evidence your key is wrong), the non-interactive guard, and the
shadowing-variable list. The interactive path is validated by driving the real
binary under a pty with `expect`, which is a weaker guarantee **because it does
not run in CI**. That is a tracked gap, not a claim.

`prompt.ts` reached 77% by faking `process.stdin` and driving `askSecret` byte
by byte — worth doing directly, because every branch there is a way to leak or
corrupt a credential: an echoed character puts the key on screen, an unhandled
Ctrl-C traps the user in a prompt raw mode has stopped generating SIGINT for,
and a pasted control character silently changes the value saved.

`target.ts` — which fetches and extracts untrusted third-party code — is at 92%,
including the integrity-mismatch refusal and the path-traversal rejection, and
is tested against a real git repository rather than a stub.

---

## 1a. What an adversarial audit found

This document's credibility depends on it recording the bad news too. In August
2026 two audits built adversarial fixtures and scored them against real
artifacts. The population did not merely fail to separate — it inverted:

| Artifact                                                             | Score |
| -------------------------------------------------------------------- | ----- |
| 76-word lorem-ipsum stub                                             | 100.0 |
| Skill with live-shaped keys, an injection payload, hidden characters | 92.9  |
| Real `anthropics/skills` artifacts                                   | ~92   |
| A **correct** skill using `description: >`                           | 83.4  |

The cause was structural: every check read a manifest, a filename or a word
count, and none opened a file body. A stub satisfies presence and length
perfectly, and so does an attack.

Separately, the artifact under evaluation supplied the policy that graded it —
`assay.config.json` inside a fetched tree was honoured, so four lines of JSON
took a skill committing a live AWS key from 47.5 to 68.2 and exit 0, while
reporting "100% measured".

Both are fixed; the same fixtures now score 46.9 and 100. They are recorded here because "we found this
ourselves and it was bad" is the only kind of statement that makes the rest of
this document worth reading.

**What this implies about the validation below.** The "37 real artifacts, zero
false failures" figure is a _specificity_ measurement. It can only detect false
positives. It cannot see a false negative, which is exactly the failure the
audit found. A corpus with labelled positives and minimal pairs is the missing
piece, and it is listed in §6.

---

## 2. Coverage by axis

| Axis          | Checks | Notes                                                                           |
| ------------- | ------ | ------------------------------------------------------------------------------- |
| **integrity** | 12     | Manifest, identity, entry resolution, per-kind well-formedness                  |
| **safety**    | 11     | File contents, credential leaks, install scripts, dependency bounds, tool scope |
| **care**      | 12     | Description quality, docs, body substance, maintenance signals                  |
| **behavior**  | 1      | The behavioral engine, via `createBehavioralCheck`                              |

All four axes now produce real verdicts. Note that `behavior` is a single
_check_ backed by an entire engine — four kind-specific harnesses, a judge, and
an adversarial probe corpus — not a single assertion.

---

## 3. What is implemented

| Capability                                                                                     | Status                                                                                    |
| ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Capability-enforced determinism tiers                                                          | **Working** — a `deterministic` check requesting a capability fails to load               |
| Capability sandboxing of checks                                                                | **Working** — undeclared capabilities are `undefined` at runtime                          |
| Error isolation (`error` ≠ `fail`)                                                             | **Working**                                                                               |
| Per-check timeouts                                                                             | **Working**, with the caveat in §5                                                        |
| Content-addressed subject digest                                                               | **Working** — transport-independent Merkle fold                                           |
| Four-axis scoring with coverage + floors                                                       | **Working**                                                                               |
| Shelf life and retraction tombstones                                                           | **Working**                                                                               |
| Static check catalog (43 checks, 4 kinds)                                                      | **Working**                                                                               |
| Behavioral engine (4 harnesses, judge, probes)                                                 | **Working** — exercised against in-memory fakes in CI, and against real artifacts by hand |
| Transcript recording + digesting                                                               | **Working**                                                                               |
| **Transcript publication** (`FileTranscriptSink`)                                              | **Working** — content-addressed, self-sufficient records                                  |
| **Replay** (`replayTranscript`)                                                                | **Working** — re-judges a stored transcript, reports agreement + drift                    |
| **Signing** (ed25519 + DSSE PAE)                                                               | **Working** — `assay sign`, `assay keygen`                                                |
| **Verification** (`assay verify`)                                                              | **Working** — score recomputation, digest match, signature                                |
| Local directory evaluation (`DirectorySource`)                                                 | **Working** — realpath containment                                                        |
| CLI (`doctor`, `init`, `run`, `verify`, `diff`, `replay`, `list`, `explain`, `sign`, `keygen`) | **Working**                                                                               |
| Vendor adapters (podman, E2B, 4 model providers)                                               | **Ported**, excluded from coverage — see §4                                               |
| Sigstore keyless signing                                                                       | **Implemented.** `assay sign --keyless`, verified in CI against real Fulcio and Rekor     |
| Config file + waivers                                                                          | **Working** — mandatory published reason, optional expiry                                 |
| SARIF 2.1.0 output                                                                             | **Working** — `--sarif`, for GitHub code scanning                                         |
| Report diffing                                                                                 | **Working** — `assay diff`, exits 1 only on a regression                                  |
| `assay replay` as a CLI subcommand                                                             | **Implemented.** `assay replay <report> --transcripts <dir>`                              |
| OTel `gen_ai.evaluation.result` emission                                                       | **Not implemented**                                                                       |

### What verification actually proves

`assay verify` answers three questions independently, and it is worth being
precise about which:

1. **Is this report about the artifact I have?** — recomputes the tree digest
   from `--artifact`.
2. **Does the score follow from the findings?** — recomputes it from `results`
   under the named formula. **This holds even against someone holding the
   signing key**: re-signing an altered report yields a valid signature over an
   inconsistent document, and the recomputation catches it anyway. There is a
   test for exactly that.
3. **Did the claimed signer sign it?** — ed25519 over the DSSE
   pre-authentication encoding, which binds the payload type so a signature can
   never be reinterpreted across document types.

### What replay actually proves

Replay verifies the **grade, not the run**. It answers "given this transcript,
was the judgement fair?" — cheaply, offline, without a sandbox. It does _not_
answer "is this transcript what the artifact really did?", which requires
re-running.

Those are different disputes, and being able to have the cheap one on its own is
most of the value. `ReplayOutcome.drift` is reported alongside agreement,
because sustained drift on unchanged inputs is the signature of a provider
silently swapping a model under a stable name — something nothing else in this
ecosystem detects.

---

## 4. Known gaps

**`deps-no-known-vulns` is implemented and queries OSV live.** It still refuses
to report a clean result for work it did not do: it `skip`s without network, and
`warn`s rather than passing when a dependency range has no concrete version to
query. That guard exists because an early version returned **`pass`** with the
summary _"Scanned N direct dependencies; no high or critical advisories"_ and a
fabricated OSV evidence URL — while never calling `ctx.net`.

It queries the LOWER bound of a declared range. `^1.2.3` resolves to something
≥1.2.3, so querying the floor may report advisories already fixed in the
installed tree — a false positive a reader can dismiss. Assuming latest would do
the opposite and miss real ones, which is the error that matters.

**Vendor adapters are excluded from coverage** (`src/adapters/**`, ~800 LOC):
podman, E2B, Anthropic, OpenAI, OpenRouter, and a local OpenAI-compatible
client. Each is a thin translation layer over a third-party SDK, so an offline
unit test would assert only that our mock matches our own mock. They need
contract tests against real vendors, which need credentials. **This is a real
gap** and is stated here rather than left implicit — hidden exclusions are how
coverage numbers start lying.

**Branch coverage sits at 79%, below the 85% used for the other three.** The MCP
and plugin harnesses are dense with defensive branches for third-party shapes we
do not control — malformed JSON-RPC frames, exotic manifest layouts, servers
dying mid-handshake. The threshold is set to 75 in `vitest.config.ts` with that
reasoning inline.

**Keyless signing cannot be tested locally.** It needs a real OIDC identity,
real Fulcio, and real Rekor. Mocking Sigstore would only prove our mock matches
our mock, so the end-to-end path is exercised by the `keyless.yml` workflow
instead — which signs, verifies against this workflow's identity, and asserts
that both a wrong identity and a tampered report are rejected. What is unit
tested locally is the guidance a developer hits when their environment cannot
do it.

**Surface capture is only as good as the run that produced it.** A static
capture reads declared registrations from source and catches a source-level
edit. A behavioral run captures what the server actually returned and
additionally catches the declared-vs-observed mismatch. But a server that
behaves differently under conditions the run did not trigger — a date, a
config flag, a remote fetch — is still invisible. That is the standing limit
of dynamic analysis, not a gap to close.

### Validated against real artifacts

Assay has been run against **37 real artifacts** — 10 skills from
`anthropics/skills`, 7 MCP servers from `modelcontextprotocol/servers`, and 10
agents plus 10 plugins from `wshobson/agents`. Zero false failures, zero errors,
scores 84–99.

That validation found four false positives, all of them presence checks that had
encoded one ecosystem's convention as universal — including one that failed all
ten official Anthropic skills. All four are fixed.

---

## 5. Structural limits

These are not gaps to close. They are the standing limits of the technique, and
a threat model that lists only wins is marketing.

**Dynamic analysis observes only paths it triggers.** A sandbox run exercises
the cases we synthesized or the author supplied. Code on an untaken branch is
unobserved, and "no malicious behavior" means "none on the paths we exercised."

**Sandbox-evasive and time-delayed payloads defeat it.** Malware that detects
virtualization, waits for a date, or fetches its payload after install will look
clean.

**Models detect evaluation.** Anthropic published (6 Mar 2026) that Claude Opus
4.6 behaves differently when it infers it is being evaluated. That is an
unresolved validity problem for every behavioral number this framework produces,
including ours.

**The lethal trifecta is not a property of any artifact.** Private data +
untrusted content + external communication is a property of the _user's whole
tool graph_. Every individual artifact can pass and the combination still be
unsafe. No per-artifact evaluation can see this.

**Capability scoping is not a JS sandbox.** A malicious check running in-process
could still reach Node built-ins directly. Treat third-party checks as you would
any dependency.

**Per-check timeouts abandon rather than cancel.** `Promise.race` stops waiting;
it does not stop the check. `ctx.signal` is aborted so cooperative checks
unwind, but an uncooperative one keeps consuming resources until the process
exits.

**Presence checks are presence checks.** `license-present` does not parse SPDX
or detect a LICENSE file containing the wrong license. `no-sensitive-files`
matches filenames, not contents — a credential hardcoded in `config.js` is
invisible to it.

---

## 6. Reproducing these numbers

```bash
npm run test:coverage
```

Per-check status in §2 and §4 is asserted by `tests/catalog.test.ts`, including
the regression guard on the false-pass bug.
