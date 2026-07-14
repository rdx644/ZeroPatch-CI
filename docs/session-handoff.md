# ZeroPatch CI ? Session Handoff

## Current state

The local/demo project is finalized after a security and correctness hardening pass.

- Workflow parsing and remediation use YAML node positions, not line regexes.
- Only approved, exact transformations are auto-remediable.
- Every candidate patch is YAML-validated and re-scanned before successful evidence is returned.
- Unsupported actions, ambiguous runner labels, and ZP005 artifact execution are review-only and rejected by `/api/remediate`.
- The optional GPT rationale is disabled by default and requires both `OPENAI_API_KEY` and `ZEROPATCH_ALLOW_AGENT=1`.
- The dashboard has no external font dependency or dynamic HTML rendering for API data.
- Docker runs as a non-root user and binds port 8000 correctly.

## Verification completed

- Unit tests: 9 passed.
- Behavioral evals: 2 passed.
- API scan/remediation smoke test passed.
- Dependency check passed.
- JavaScript syntax check passed.
- Whitespace validation passed.

## Known environment limitation

This review environment denies writes to pre-existing `__pycache__` and `evals/results/latest.json`. The application and tests run with `python -B`; the eval runner now reports successful output to stdout if its optional results file cannot be persisted.

## Read next

See `docs/finalization.md` for the audit-to-fix matrix and `docs/security_best_practices_report.md` for the original detailed audit.
