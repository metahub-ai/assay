# Assay GitHub Action

Run [Assay](https://github.com/metahub-ai/assay) in CI and surface its findings in the GitHub **Security → Code scanning** tab, with per-line annotations on pull requests. Assay emits SARIF 2.1.0, so no extra tooling is needed — this action runs the evaluation, uploads the SARIF, and optionally fails the job on a blocking finding or a score gate.

## Quick start

```yaml
name: Assay
on:
  push:
  pull_request:

permissions:
  contents: read
  security-events: write # required to upload SARIF to code scanning

jobs:
  assay:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: metahub-ai/assay/action@v1
        with:
          path: .
          # kind is auto-detected; set it to skip detection
          # kind: mcp
```

That runs the **static** tier (fast, no credentials) over the repository, uploads the report, and fails the job if a blocking check fails.

## Gate on a score

```yaml
- uses: metahub-ai/assay/action@v1
  with:
    suite: assay:strict # fails below 85 by default
    min-score: 90 # or set your own bar
```

## Run the behavioral tier

The behavioral tier boots the artifact in a sandbox and drives it with a model, so it needs a sandbox and provider credentials. Keep it off for pull requests from forks.

```yaml
- uses: metahub-ai/assay/action@v1
  with:
    behavioral: "true"
    args: "--sandbox e2b"
  env:
    E2B_API_KEY: ${{ secrets.E2B_API_KEY }}
    OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
```

## Inputs

| Input           | Default               | Description                                                                     |
| --------------- | --------------------- | ------------------------------------------------------------------------------- |
| `path`          | `.`                   | Path to the artifact to evaluate.                                               |
| `kind`          | _(auto)_              | `skill` \| `mcp` \| `agent` \| `plugin`. Omit to auto-detect.                   |
| `suite`         | _(default)_           | `assay:recommended` \| `assay:strict` \| `assay:mcp-server`, or a custom label. |
| `min-score`     | _(none)_              | Fail when the overall score is below this (0-100).                              |
| `behavioral`    | `false`               | Run the behavioral tier (needs a sandbox + credentials).                        |
| `args`          | _(none)_              | Extra raw arguments appended to `assay run`.                                    |
| `version`       | `latest`              | Version of `@metahub-ai/assay` to run.                                          |
| `sarif-file`    | `assay-results.sarif` | Where to write the SARIF report.                                                |
| `upload`        | `true`                | Upload the SARIF to code scanning (needs `security-events: write`).             |
| `fail-on-error` | `true`                | Fail the job when assay exits non-zero.                                         |

## Outputs

| Output       | Description                                                                             |
| ------------ | --------------------------------------------------------------------------------------- |
| `sarif-file` | Path to the generated SARIF file.                                                       |
| `exit-code`  | `assay run` exit code: `0` clean, `1` blocking failure / gate tripped, `2` usage error. |

## Notes

- **Findings still upload even when the job fails.** The SARIF is uploaded before the gate is enforced, so a blocking failure both annotates the PR and fails the build.
- **Pin the version** in production (`version: 0.5.0`) so a new release cannot change your gate under you.
- The action pins `security-severity` and `helpUri` per rule, so code scanning ranks and links findings correctly.
