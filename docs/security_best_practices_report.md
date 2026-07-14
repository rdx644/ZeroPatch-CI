# ZeroPatch CI security and code-review audit

## Executive summary

The application has a good safety intent: it does not execute workflow code and it blocks direct remediation of ZP005. However, the current regex-only parser and patcher can alter ordinary workflow script text, produce invalid YAML, and still report that the selected policy checks passed. This makes the remediation evidence untrustworthy enough to block release until fixed. The audit also found material detection gaps, unsupported remediation paths presented as available, and Docker/API deployment weaknesses.

The review covered all application, frontend, test, evaluation, Docker, dependency, and documentation files. No secrets were read or recorded.

## High severity

### ZP-AUD-001 — A successful remediation can be syntactically invalid

- **Rule IDs:** FASTAPI-VALID-001, FASTAPI-RESP-001
- **Severity:** High
- **Location:** `app/scanner.py:45-48`, `app/remediator.py:28-31`, `app/validator.py:7-14`
- **Evidence:**

  ```python
  if "uses:" in line and "@" in line:
      ref = line.rsplit("@", 1)[1].split()[0]
  ...
  patched = re.sub(rf"({re.escape(action)}@)(?![0-9a-fA-F]{{40}})([^\s#]+)", rf"\g<1>{sha}", patched)
  ...
  remaining = {finding.rule_id for finding in scan_workflow(after)}
  ```

  A workflow step containing `run: echo "uses: actions/checkout@v4"` is classified as ZP001. Selecting it replaces text inside the quoted shell command and removes the closing quote. The API then returns HTTP 200 with the first two evidence checks `passed`; `yaml.safe_load()` rejects the returned workflow with `ScannerError`.
- **Impact:** A reviewer can be told that a broken, invalid workflow was remediated successfully. The app has no merge authority, which limits the blast radius, but this defeats its evidence-first safety promise.
- **Fix:** Parse workflows with a GitHub-Actions-aware YAML AST; inspect only `steps[*].uses` scalar nodes and rewrite only those node values. Parse the candidate YAML after transformation and reject it if invalid. Treat a failed structural validation as an API error, not successful evidence.
- **Mitigation:** Until the parser is replaced, do not offer ZP001 auto-remediation for arbitrary input.
- **False-positive notes:** Reproduced through `/api/scan` and `/api/remediate` with `use_agent: false`.

### ZP-AUD-002 — Most ZP001 findings are offered for remediation but cannot be fixed

- **Severity:** High
- **Location:** `app/scanner.py:45-48`, `app/remediator.py:11-16`, `app/main.py:44,80-83`
- **Evidence:** The scanner flags every non-40-character `uses:` reference, but `PINS` contains only four actions. `fixable` is calculated as `raw.rule_id != "ZP005"`, so every ZP001 finding is selectable even when no pin exists.
- **Impact:** For `acme/example-action@v1`, `/api/remediate` returns HTTP 200 without changing the workflow and with failed evidence. That is a broken user path and makes the "select safe repairs" UI claim inaccurate.
- **Fix:** Set `fixable` only when the exact action is in an approved pin catalog and its YAML node is eligible. Otherwise label it review-only and explain how to supply an approved commit SHA. Reject a remediation request that has no supported transformations.
- **Mitigation:** Include the exact supported-action set in the UI until support is generalized.
- **False-positive notes:** Reproduced with a one-step workflow using `acme/example-action@v1`.

### ZP-AUD-003 — ZP005 misses common untrusted-artifact execution flows

- **Severity:** High
- **Location:** `app/scanner.py:49-52`
- **Evidence:**

  ```python
  if re.search(r"(download-artifact|actions/cache).*(run:|bash|sh)", line, re.I):
  if "./artifact" in line or "bash artifact" in line:
  ```

  Detection is line-local and does not connect a preceding `actions/download-artifact` step to a later execution step.
- **Impact:** A workflow that downloads an artifact and executes `node dist/app.js` is not reported as ZP005. It is only reported as unpinned ZP001, which can then be remediated while the critical artifact-execution risk remains undetected.
- **Fix:** Parse jobs and ordered steps. Track artifact download/cache restore locations and flag later commands that execute files from those paths (shell, Node, Python, PowerShell, binaries), with an explicit conservative review-only fallback where provenance is ambiguous.
- **Mitigation:** State that ZP005 is a narrow heuristic, not a high-confidence general control, until data-flow-aware detection exists.
- **False-positive notes:** Reproduced with `actions/download-artifact@v4` followed by `run: node dist/app.js`.

## Medium severity

### ZP-AUD-004 — ZP004 ignores whether a self-hosted runner handles pull-request code

- **Severity:** Medium
- **Location:** `app/scanner.py:39-40`, `app/remediator.py:23-24`
- **Evidence:** Any line containing `runs-on:` and `self-hosted` is reported and rewritten, with no trigger, job, checkout, or trust-boundary analysis.
- **Impact:** A trusted `workflow_dispatch` deployment job is flagged and its runner changed to `ubuntu-latest`, potentially breaking a required deployment capability even though the stated rule is "Self-hosted runner in PR path."
- **Fix:** Scope this control to workflows/jobs reachable from untrusted PR events and retain the job context in findings. Make non-PR self-hosted use review-only, with contextual guidance rather than an automatic runner change.
- **Mitigation:** Do not auto-remediate ZP004 outside an explicitly verified PR-code path.

### ZP-AUD-005 — ZP002 leaks its permissions scope into later workflow content

- **Severity:** Medium
- **Location:** `app/scanner.py:33,41-44`
- **Evidence:** `saw_permissions` is set once and never reset; every later line containing `write` or `all` is reported.
- **Impact:** A valid workflow with `permissions: contents: read` followed by `run: echo write` produces ZP002 on the shell-command line. `permissions: read-all` is also reported but is not transformed by the remediator, yielding failed evidence.
- **Fix:** Parse the `permissions` mapping or compact form only; evaluate its values, reset scope when leaving the mapping, and either support each detected form or mark it review-only.
- **Mitigation:** Add regression tests for nested jobs, shell text, `read-all`, `write-all`, and per-permission `write` values.

### ZP-AUD-006 — Public remediation can trigger unbounded third-party model calls

- **Rule ID:** FASTAPI-AUTH-001 / FASTAPI-LIMITS-001
- **Severity:** Medium (if reachable outside a trusted local environment)
- **Location:** `app/schemas.py:37-39`, `app/main.py:71-83`, `app/remediator.py:37-53`
- **Evidence:** The unauthenticated `/api/remediate` route accepts up to 100 KB of caller-controlled workflow text and defaults `use_agent` to `True`; when an API key is configured, it sends the first 12,000 characters to the external model service.
- **Impact:** An internet-exposed deployment could be used for API-cost abuse and to inject untrusted workflow text into the reviewer-rationale prompt. It cannot execute the workflow, but the cost and output-integrity boundary are unprotected.
- **Fix:** Keep the app local by default, require authentication before agent use, rate-limit/budget requests, make agent use opt-in by default, and clearly delimit untrusted input in the model prompt. Consider moving external rationale generation behind a trusted server-side queue.
- **Mitigation:** Disable `use_agent` in deployments without auth/rate limits.
- **False-positive notes:** This is conditional on public or shared deployment; the documented direct app startup binds loopback.

### ZP-AUD-007 — Docker deployment is unreachable through its documented port mapping

- **Severity:** Medium
- **Location:** `Dockerfile:8`, `app/main.py:86-88`, `README.md:31-34`
- **Evidence:** Docker starts `python -m app.main`, which invokes `uvicorn.run(..., host="127.0.0.1", ...)`. The process listens only on the container loopback interface, while the README advertises `docker run -p 8000:8000`.
- **Impact:** The mapped host port cannot reach the service, so the documented container deployment does not work. The container also runs as root and has no production proxy/worker/timeout settings.
- **Fix:** Use a production ASGI command that binds `0.0.0.0` in the container; run as an unprivileged user; document proxy and request-limit expectations. Keep the direct local entry point bound to loopback.
- **Mitigation:** Treat the Dockerfile as development-only until corrected.

## Low severity / hardening

### ZP-AUD-008 — Browser and API responses have no visible security headers

- **Rule IDs:** FASTAPI-HEADERS-001, JS-CSP-001
- **Severity:** Low
- **Location:** `app/main.py:31-32`, `web/index.html:7-10`
- **Evidence:** The app serves HTML and static JavaScript but does not install header middleware; an HTTP test response had no CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, or `Permissions-Policy` headers.
- **Impact:** No direct DOM XSS was found: workflow and model-summary content use `textContent`, and the remaining `innerHTML` values are app-controlled. Still, security headers would reduce impact if a future rendering path regresses.
- **Fix:** Add headers centrally or at the reverse proxy. Prefer a header-delivered restrictive CSP that permits the two required Google Fonts origins (or self-host fonts), sets `default-src 'self'`, and restricts framing with `frame-ancestors` at the header layer.
- **Mitigation:** Verify whether a production edge already supplies equivalent headers before duplicating them.

### ZP-AUD-009 — Regression coverage does not exercise the unsafe and unsupported paths

- **Severity:** Low
- **Location:** `tests/test_scanner.py:14-29`, `evals/run_local.py:10-27`
- **Evidence:** The three unit tests and two eval cases use only the fixture's happy path. They do not cover syntax validation, generic actions, multiline/scoped YAML, trusted self-hosted jobs, artifact data flow, or API response status when no patch is possible.
- **Impact:** The demonstrated defects pass the existing test suite, so regressions in the safety boundary are not caught.
- **Fix:** Add API-level tests for every reproduction in this report and require YAML parsing plus re-scan validation before an evidence result can pass.

## Verification performed

- `python -m unittest discover -s tests -v`: 3 passed.
- `python evals/run_local.py`: could not rewrite `evals/results/latest.json` in this review environment because of a local permission denial; the existing results file shows the two prior cases passed. This is an environment limitation, not counted as a project defect.
- `python -m pip check`: no broken requirements.
- API-level reproductions used FastAPI's in-process test client with agent use disabled; no workflow code was executed and no secret values were read.

## Recommended release gate

Do not present remediation evidence as release-ready until ZP-AUD-001, ZP-AUD-002, and ZP-AUD-003 are resolved and covered by regression tests. The fastest safe direction is to replace regex patching with structure-aware workflow parsing and make unsupported or ambiguous cases explicitly review-only.
