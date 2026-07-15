# ZeroPatch CI

Evidence-first GitHub Actions supply-chain remediation. ZeroPatch parses a workflow, scans five high-confidence controls, ranks findings with transparent indicators, and creates a **draft-only** remediation artifact with structural validation evidence.

For the hackathon narrative, architecture, 90-second demo, and judging proof, read [the Build Week submission brief](docs/hackathon_submission.md).

## Safety boundary

- YAML node positions?not raw text regexes?drive finding detection and changes.
- Transformations are restricted to approved action SHA pins, least-privilege permissions, safe PR triggers, and exact self-hosted runner replacements.
- Unsupported, ambiguous, and artifact-execution findings are review-only; the API rejects attempts to auto-remediate them.
- Candidate patches must parse as YAML and remove every selected finding before evidence can be returned.
- ZeroPatch never executes repository code and has no merge authority.
- Optional GPT-5.6 rationale is disabled by default and receives only delimited, untrusted workflow text.

## Run locally

Requires Python 3.11+.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m unittest discover -s tests -v
python evals\run_local.py
python -m app.main
```

Open `http://127.0.0.1:8000`. The dashboard loads `fixtures/insecure-release.yml` automatically.

To enable the optional reviewer rationale for a trusted local session, put `OPENAI_API_KEY` in `.env.local`, set `ZEROPATCH_LOAD_DOTENV=1`, and set `ZEROPATCH_ALLOW_AGENT=1`. Keep this option disabled for shared or public deployments unless an authenticated, rate-limited service boundary is added.

## Docker

```powershell
docker build -t zeropatch-ci .
docker run --rm -p 8000:8000 zeropatch-ci
```

The container runs as an unprivileged user and listens on `0.0.0.0:8000`. The default trusted hosts are `localhost` and `127.0.0.1`; for a reverse-proxied deployment, set `ZEROPATCH_ALLOWED_HOSTS` to an explicit comma-separated hostname allowlist. Apply TLS, request-size limits, and rate limits at that edge.

## Production deployment

`render.yaml` provisions the web service and its PostgreSQL audit database. Before applying the Blueprint, set these Render secrets (never commit them):

- `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`
- `ZEROPATCH_SESSION_SECRET` (a long random value)
- `ZEROPATCH_ADMIN_LOGINS` (comma-separated GitHub login names permitted to read `/api/audit`)

The production callback URL is `https://zeropatch-ci-rdx644.onrender.com/auth/github/callback`. The deployment requires the database to be healthy before it is considered ready. GitHub OAuth protects scan and remediation operations; optional unattended clients may instead send a value from `ZEROPATCH_API_KEYS` in the `X-ZeroPatch-Key` header. Rotate that secret outside the repository.
## Policy controls

| Rule | Control | Automated remediation |
| --- | --- | --- |
| ZP001 | Unpinned GitHub Action | Approved catalog entries only; other actions are review-only |
| ZP002 | Explicit write token permission | Change selected `write` values to `read` |
| ZP003 | `pull_request_target` | Change to `pull_request` |
| ZP004 | Self-hosted runner in a PR workflow | Change an exact `self-hosted` label to `ubuntu-latest` |
| ZP005 | Downloaded artifact later executed | No ? requires human redesign |

## Verification

The test suite includes parser, transformation, artifact-flow, permissions-scope, API rejection, and response-header regressions. Review the generated draft patch before opening any PR; evidence proves only the bounded static checks, not runtime workflow behavior.

## Use as a GitHub Action

ZeroPatch can run in any GitHub Actions repository without running the repository workflows it inspects. It writes a redacted JSON report, step-summary counts, and can fail the check at a selected severity.

```yaml
- uses: rdx644/ZeroPatch-CI@v1.0.0
  with:
    workflow-path: .github/workflows
    report-path: .zeropatch/zeropatch-report.json
    fail-on: critical
```

Available outputs are `report-path`, `finding-count`, and `blocking-findings`. Use `fail-on: never` for report-only mode. Pin the action to the immutable commit SHA behind the release tag in production workflows. See [GitHub Action usage](docs/github-action.md) for the complete contract.
