# ZeroPatch CI - Build Week Submission

## One-line pitch

**ZeroPatch CI turns risky GitHub Actions workflows into evidence-backed, review-ready repair drafts without running untrusted code or taking merge authority.**

## The problem

CI configuration is executable supply-chain policy. A mutable action tag, `pull_request_target` trigger, write-scoped token, self-hosted PR runner, or downloaded artifact can turn a routine workflow change into a repository compromise. Existing scanners stop at a warning; teams still have to translate a finding into a safe, reviewable change.

## What makes ZeroPatch different

ZeroPatch is an **evidence-bound remediation system**, not a generic YAML linter or a "fix everything" agent.

1. It parses a YAML node graph, so shell text is never mistaken for workflow configuration.
2. Transparent ranking decides review order; deterministic policy controls decide what may change.
3. Only exact, approved transformations are applied to AST-derived node spans.
4. Each candidate is reparsed and re-scanned before the proof bundle is returned.
5. Ambiguous cases, custom actions, and untrusted-artifact execution are deliberately review-only.

The boundary is the product: helpful enough to reduce remediation time, constrained enough to deserve trust.

## Who it helps

- Open-source maintainers who accept pull requests.
- Platform and DevSecOps teams standardizing GitHub Actions controls.
- Security reviewers who need an auditable draft rather than another alert queue.

## Live demo - 90 seconds

1. Load the deliberately insecure release workflow.
2. Show the posture score and ordered queue: trigger, permissions, runner, mutable tags, and artifact execution.
3. Select safe repairs. Artifact execution stays disabled because it cannot be safely auto-fixed.
4. Generate the draft. The proof panel confirms valid YAML, minimal change, cleared selected controls, non-execution, and a human gate.
5. Enable the optional OpenAI reviewer rationale. It explains a bounded change but never selects, edits, executes, or merges.
6. Edit the source after scanning. The evidence snapshot clears, so a patch cannot target stale source.

## Architecture

```text
Workflow YAML -> node parser + policy scanner -> transparent ranking
                      |
                      +-> approved node transforms -> reparse + rescan
                      |                                  |
                      +-> review UI <- evidence bundle <- draft patch
                                                   |
                                             human approval
```

The GitHub Action uses the same scanner and emits a redacted JSON report, GitHub outputs, and a configurable severity gate. It never runs a scanned workflow.

## OpenAI and Codex implementation

The safety-critical path is deterministic. The OpenAI Agents SDK is an opt-in reviewer-rationale layer; workflow text is delimited as untrusted data and the deterministic fallback keeps the product usable without a key or during an API outage. Codex drove the audit, AST-safe remediation refactor, test expansion, UI polish, and end-to-end verification. The result is inspectable in the source tree rather than hidden behind a black-box demo.

## Proof for judges

| Criterion | Concrete evidence |
| --- | --- |
| Technological implementation | YAML node traversal, exact range patches, reparse/rescan evidence, FastAPI API, GitHub Docker Action, and guarded Agents SDK rationale. |
| Design | Responsive bento command center with liquid-glass surfaces, operational states, accessible notices, review-only affordances, and a visible human gate. |
| Potential impact | Targets risky CI changes before they reach repositories. |
| Quality and novelty | Combines static supply-chain controls with narrow remediation and proof artifacts; it optimizes for justified trust, not autonomous action. |

## Judge checklist

- Run `python -B -m unittest discover -s tests -v` and `python -B evals/run_local.py`.
- Open the app, generate a safe draft, and inspect the evidence bundle.
- Confirm review-only findings cannot be selected.
- Modify the source after scanning and confirm the review state invalidates.
- Inspect the GitHub Action report and severity threshold.

## Honest constraints

ZeroPatch does not claim to prove runtime workflow safety. ZP005 is intentionally conservative and same-job only; complex provenance needs a future data-flow engine. A public deployment still needs authentication, rate limits, request-size limits, TLS, and an edge proxy. Being explicit about those limits is part of the trust model.
