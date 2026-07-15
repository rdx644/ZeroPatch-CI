from __future__ import annotations

import os
import secrets
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .audit import AuditStore
from .auth import begin_github_login, current_identity, github_identity, is_admin, service_identity
from .limits import RateLimiter
from .remediator import PatchError, agent_summary, deterministic_patch, patch_id
from .risk import TransparentRiskRanker, posture
from .scanner import WorkflowParseError, scan_workflow
from .schemas import Finding, RemediationRequest, RemediationResponse, ScanRequest, ScanResponse
from .validator import validate


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "web"
FIXTURES = ROOT / "fixtures"


def load_local_env() -> None:
    """Allow an explicit local-only convenience file without production secret leakage."""
    if os.getenv("ZEROPATCH_LOAD_DOTENV") != "1":
        return
    env_file = ROOT / ".env.local"
    if env_file.exists() and not os.getenv("OPENAI_API_KEY"):
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("OPENAI_API_KEY="):
                os.environ["OPENAI_API_KEY"] = line.split("=", 1)[1].strip()


load_local_env()
session_secret = os.getenv("ZEROPATCH_SESSION_SECRET")
if not session_secret:
    if os.getenv("ZEROPATCH_ENV") == "production":
        raise RuntimeError("ZEROPATCH_SESSION_SECRET must be configured in production.")
    session_secret = secrets.token_urlsafe(32)

app = FastAPI(title="ZeroPatch CI", version="0.3.0", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=session_secret,
    same_site="lax",
    https_only=os.getenv("ZEROPATCH_ENV") == "production",
    max_age=28800,
)
allowed_hosts = [host.strip() for host in os.getenv("ZEROPATCH_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver").split(",") if host.strip()]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
app.mount("/assets", StaticFiles(directory=STATIC), name="assets")
ranker = TransparentRiskRanker()
audit_store = AuditStore()
audit_store.initialize()
rate_limiter = RateLimiter()


def secure_response(response: Response, request: Request) -> Response:
    response.headers.setdefault("X-Request-Id", request.headers.get("X-Request-Id", secrets.token_hex(12)))
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


@app.middleware("http")
async def security_headers(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > 110_000:
                    return secure_response(JSONResponse(status_code=413, content={"detail": "Request body exceeds the 100 KB limit."}), request)
            except ValueError:
                return secure_response(JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header."}), request)
        try:
            rate_limiter.check(request)
        except HTTPException as exc:
            return secure_response(JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=exc.headers), request)
    return secure_response(await call_next(request), request)


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


def require_api_identity(request: Request) -> dict[str, object]:
    """Accept an automation key or an interactive identity in protected deployments."""
    service = service_identity(request)
    if service:
        return dict(service)
    if os.getenv("ZEROPATCH_AUTH_REQUIRED") == "1":
        return dict(current_identity(request))
    return {"login": "anonymous"}


def require_admin(request: Request) -> dict[str, object]:
    identity = require_api_identity(request)
    if not is_admin(identity):
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    return identity

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "zeropatch-ci"}


@app.get("/health/ready")
def ready() -> JSONResponse:
    if audit_store.ready():
        return JSONResponse({"status": "ok", "database": "ready"})
    return JSONResponse(status_code=503, content={"status": "degraded", "database": "unavailable"})


@app.get("/auth/github/login")
def github_login(request: Request) -> RedirectResponse:
    return RedirectResponse(begin_github_login(request), status_code=302)


@app.get("/auth/github/callback", name="github_callback")
async def github_callback(request: Request, code: str, state: str) -> RedirectResponse:
    request.session["identity"] = await github_identity(request, code, state)
    return RedirectResponse("/", status_code=303)


@app.post("/auth/logout")
def logout(request: Request) -> dict[str, bool]:
    request.session.clear()
    return {"ok": True}


@app.get("/api/me")
def current_user(request: Request) -> dict[str, object]:
    identity = require_api_identity(request)
    authenticated = identity["login"] != "anonymous"
    return {
        "login": identity["login"],
        "admin": is_admin(identity),
        "authenticated": authenticated,
        "auth_required": os.getenv("ZEROPATCH_AUTH_REQUIRED") == "1",
    }


@app.get("/api/audit")
def audit_events(request: Request, limit: int = 50) -> dict[str, object]:
    require_admin(request)
    if not audit_store.ready():
        raise HTTPException(status_code=503, detail="Audit storage is unavailable.")
    return {"events": audit_store.recent(limit)}

@app.get("/")
def dashboard() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/sample")
def sample() -> dict[str, str]:
    return {"workflow": (FIXTURES / "insecure-release.yml").read_text(encoding="utf-8"), "source_name": "insecure-release.yml"}


@app.post("/api/scan", response_model=ScanResponse)
def scan(request: Request, payload: ScanRequest) -> ScanResponse:
    actor = require_api_identity(request)
    try:
        result = build_response(payload.workflow, payload.source_name)
        if not audit_store.record("scan", str(actor["login"]), payload.source_name, len(result.findings)):
            raise HTTPException(status_code=503, detail="Audit storage is unavailable.")
        return result
    except WorkflowParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/remediate", response_model=RemediationResponse)
async def remediate(request: Request, payload: RemediationRequest) -> RemediationResponse:
    actor = require_api_identity(request)
    try:
        raw_findings = scan_workflow(payload.workflow)
    except WorkflowParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    by_id = {f"{raw.rule_id}-{raw.line}-{index}": raw for index, raw in enumerate(raw_findings, start=1)}
    selected = [by_id[item] for item in payload.finding_ids if item in by_id]
    if len(selected) != len(set(payload.finding_ids)):
        raise HTTPException(status_code=400, detail="Select findings from the current scan only.")
    if not selected:
        raise HTTPException(status_code=400, detail="Select one or more findings from the current scan.")
    if any(not item.fixable for item in selected):
        raise HTTPException(status_code=400, detail="One or more selected findings require human review and cannot be auto-remediated.")
    try:
        patched = deterministic_patch(payload.workflow, selected)
    except PatchError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    evidence = validate(payload.workflow, patched, selected)
    if any(check.status == "failed" for check in evidence):
        raise HTTPException(status_code=409, detail="The candidate patch did not satisfy structural validation.")
    rule_ids = {item.rule_id for item in selected}
    summary, agent_mode = await agent_summary(payload.workflow, rule_ids) if payload.use_agent else ("Generated deterministic policy-bound remediation.", "deterministic-fallback")
    artifact = RemediationResponse(patched_workflow=patched, summary=summary, agent_mode=agent_mode, evidence=evidence, patch_id=patch_id(payload.workflow, patched))
    if not audit_store.record("remediate", str(actor["login"]), payload.source_name, len(selected), artifact.patch_id):
        raise HTTPException(status_code=503, detail="Audit storage is unavailable.")
    return artifact


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.getenv("PORT", "8000")))
