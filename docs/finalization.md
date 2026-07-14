# ZeroPatch CI ? Finalization record

## Release readiness

The audited implementation is ready for local/demo use. It keeps the intended human-review boundary: it never executes workflow or artifact code, never merges, and rejects unsupported automatic changes.

## Audit remediation matrix

| Audit ID | Resolution | Proof |
| --- | --- | --- |
| ZP-AUD-001 | Replaced text-regex detection and patching with PyYAML node traversal and exact node-span replacements. Candidate patches must parse as YAML before evidence is returned. | `test_remediation_only_changes_selected_safe_nodes_and_stays_valid_yaml`; API scan/remediation smoke test |
| ZP-AUD-002 | Findings carry a `fixable` property. Only actions in the approved commit-SHA catalog are selectable; unsupported actions return HTTP 400 on remediation. | `test_unsupported_action_is_review_only_and_cannot_be_remediated` |
| ZP-AUD-003 | Detection tracks `actions/download-artifact` followed by shell, Node, Python, or PowerShell execution within a job. ZP005 remains review-only. | `test_artifact_execution_is_detected_across_steps` |
| ZP-AUD-004 | Self-hosted runner detection is limited to pull-request-reachable workflows; only an exact `self-hosted` value is automatically replaceable. | `test_permissions_and_runner_are_scoped_to_their_actual_context` |
| ZP-AUD-005 | Permissions are inspected only as YAML permission nodes; shell text and `read` values no longer cause ZP002. | `test_permissions_and_runner_are_scoped_to_their_actual_context` |
| ZP-AUD-006 | Model rationale is off by default and additionally requires `ZEROPATCH_ALLOW_AGENT=1`. The workflow is delimited as untrusted data. | Schema default and `agent_summary` gate reviewed; smoke test runs with `use_agent: false` |
| ZP-AUD-007 | The container runs as an unprivileged user and starts Uvicorn on `0.0.0.0:8000`. A `.dockerignore` prevents local secrets and environments from being copied. | Dockerfile review |
| ZP-AUD-008 | Added strict security headers, Trusted Host middleware, no public API docs, removed external font dependencies, and eliminated dynamic `innerHTML` rendering. | `test_security_headers_are_present`; `node --check web/app.js`; source scan for `innerHTML` and Google Font URLs |
| ZP-AUD-009 | Expanded unit/API coverage from 3 to 9 tests, including all reported reproductions. The eval runner now preserves successful validation if its optional output file cannot be written. | 9 passing unit tests; 2 passing behavioral evals |

## Remaining intentional limits

- ZP005 is a conservative, same-job heuristic. It intentionally remains review-only; complex cross-job artifact provenance requires a broader data-flow engine.
- The optional model rationale is suitable only behind a trusted/authenticated/rate-limited deployment boundary. It is disabled by default.
- Production deployment still needs TLS, rate limiting, and request-size limits at the reverse proxy or platform edge.

## Verification commands

```powershell
python -B -m unittest discover -s tests -v
python -B evals\run_local.py
python -B -m pip check
node --check web\app.js
```

The Python bytecode compilation check is not included because this review environment denies writes to existing `__pycache__` directories. Imports, unit tests, evals, and the API smoke test all execute successfully with `-B`.
