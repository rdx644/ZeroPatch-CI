from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .remediator import PatchError, agent_summary, deterministic_patch, patch_id
from .risk import TransparentRiskRanker, posture
from .scanner import WorkflowParseError, scan_workflow
from .schemas import Finding, RemediationRequest, RemediationResponse, ScanRequest, ScanResponse
from .validator import validate


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "web"
FIXTURES = ROOT / "fixtures"


def load_local_env() -> None:
    env_file = ROOT / ".env.local"
    if env_file.exists() and not os.getenv("OPENAI_API_KEY"):
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("OPENAI_API_KEY="):
                os.environ["OPENAI_API_KEY"] = line.split("=", 1)[1].strip()


load_local_env()
app = FastAPI(title="ZeroPatch CI", version="0.2.0", docs_url=None, redoc_url=None, openapi_url=None)
allowed_hosts = [host.strip() for host in os.getenv("ZEROPATCH_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver").split(",") if host.strip()]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
app.mount("/assets", StaticFiles(directory=STATIC), name="assets")
ranker = TransparentRiskRanker()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


def build_response(workflow: str, source_name: str) -> ScanResponse:
    raw_findings = scan_workflow(workflow)
    findings: list[Finding] = []
    for index, raw in enumerate(raw_findings, start=1):
        score = ranker.score(raw, workflow)
        findings.append(Finding(
            id=f"{raw.rule_id}-{raw.line}-{index}", rule_id=raw.rule_id, title=raw.title,
            severity=raw.severity, confidence=score.confidence, line=raw.line, evidence=raw.evidence,
            recommendation=raw.recommendation, fixable=raw.fixable,
            ml_priority=score.priority, anomaly_score=score.anomaly,
        ))
    findings.sort(key=lambda item: item.ml_priority, reverse=True)
    return ScanResponse(findings=findings, posture=posture(raw_findings), source_name=source_name, scanned_lines=len(workflow.splitlines()))


@ app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "zeropatch-ci"}


@ app.get("/")
def dashboard() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@ app.get("/api/sample")
def sample() -> dict[str, str]:
    return {"workflow": (FIXTURES / "insecure-release.yml").read_text(encoding="utf-8"), "source_name": "insecure-release.yml"}


@ app.post("/api/scan", response_model=ScanResponse)
def scan(request: ScanRequest) -> ScanResponse:
    try:
        return build_response(request.workflow, request.source_name)
    except WorkflowParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@ app.post("/api/remediate", response_model=RemediationResponse)
async def remediate(request: RemediationRequest) -> RemediationResponse:
    try:
        raw_findings = scan_workflow(request.workflow)
    except WorkflowParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    by_id = {f"{raw.rule_id}-{raw.line}-{index}": raw for index, raw in enumerate(raw_findings, start=1)}
    selected = [by_id[item] for item in request.finding_ids if item in by_id]
    if len(selected) != len(set(request.finding_ids)):
        raise HTTPException(status_code=400, detail="Select findings from the current scan only.")
    if not selected:
        raise HTTPException(status_code=400, detail="Select one or more findings from the current scan.")
    if any(not item.fixable for item in selected):
        raise HTTPException(status_code=400, detail="One or more selected findings require human review and cannot be auto-remediated.")
    try:
        patched = deterministic_patch(request.workflow, selected)
    except PatchError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    evidence = validate(request.workflow, patched, selected)
    if any(check.status == "failed" for check in evidence):
        raise HTTPException(status_code=409, detail="The candidate patch did not satisfy structural validation.")
    rule_ids = {item.rule_id for item in selected}
    summary, agent_mode = await agent_summary(request.workflow, rule_ids) if request.use_agent else ("Generated deterministic policy-bound remediation.", "deterministic-fallback")
    return RemediationResponse(patched_workflow=patched, summary=summary, agent_mode=agent_mode, evidence=evidence, patch_id=patch_id(request.workflow, patched))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.getenv("PORT", "8000")))
