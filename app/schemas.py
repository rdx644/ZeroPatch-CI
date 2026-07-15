from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


Severity = Literal["critical", "high", "medium", "low"]


class Finding(StrictModel):
    id: str
    rule_id: str
    title: str
    severity: Severity
    confidence: int = Field(ge=0, le=100)
    line: int = Field(ge=1)
    evidence: str
    recommendation: str
    fixable: bool = True
    ml_priority: int = Field(ge=0, le=100)
    anomaly_score: int = Field(ge=0, le=100)


class ScanRequest(StrictModel):
    workflow: str = Field(min_length=1, max_length=100_000)
    source_name: str = Field(default="workflow.yml", min_length=1, max_length=160, pattern=r".*\S.*")


class ScanResponse(StrictModel):
    findings: list[Finding]
    posture: dict[str, int]
    source_name: str
    scanned_lines: int


class RemediationRequest(ScanRequest):
    finding_ids: list[str] = Field(min_length=1, max_length=20)
    use_agent: bool = False


class EvidenceCheck(StrictModel):
    name: str
    status: Literal["passed", "failed", "skipped"]
    detail: str


class RemediationResponse(StrictModel):
    patched_workflow: str
    summary: str
    agent_mode: Literal["gpt-5.6", "deterministic-fallback"]
    evidence: list[EvidenceCheck]
    patch_id: str
