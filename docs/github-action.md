# ZeroPatch CI GitHub Action

`rdx644/ZeroPatch-CI` is a Docker Action for statically inspecting GitHub Actions YAML. It does not check out a second repository, run workflow commands, contact GitHub APIs, or modify workflow files.

## Quick start

```yaml
name: ZeroPatch scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: rdx644/ZeroPatch-CI@v1.0.0
        with:
          workflow-path: .github/workflows
          fail-on: critical
```

For hardened production use, replace `v1.0.0` with its immutable commit SHA.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `workflow-path` | `.github/workflows` | A `.yml`/`.yaml` workflow or directory below the checked-out workspace. |
| `report-path` | `.zeropatch/zeropatch-report.json` | Output JSON path below the workspace. |
| `fail-on` | `critical` | `never`, `critical`, `high`, `medium`, or `low`. |

Malformed YAML, missing workflow paths, and workspace-path escapes fail the action with an input/configuration error. `fail-on: never` suppresses severity failures but not configuration errors.

## Outputs

| Output | Description |
| --- | --- |
| `report-path` | Relative path to the JSON report. |
| `finding-count` | Total detected findings. |
| `blocking-findings` | Findings at or above the requested severity. |

The report contains file, rule, severity, line, title, recommendation, and whether the project supports a bounded automatic remediation. It intentionally excludes raw workflow evidence to avoid copying potentially sensitive command text into CI artifacts or logs.

## Scope

The action detects the five ZeroPatch controls. ZP005, unsupported action pins, and ambiguous transformations remain human-review-only. A green check means the selected static threshold was not met; it does not prove runtime workflow safety.
