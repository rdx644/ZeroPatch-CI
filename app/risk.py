from __future__ import annotations

from dataclasses import dataclass

from .scanner import RawFinding


SEVERITY_WEIGHT = {"critical": 42, "high": 28, "medium": 16, "low": 8}
RULE_WEIGHT = {"ZP003": 20, "ZP005": 20, "ZP002": 13, "ZP004": 13, "ZP001": 8}


@dataclass(frozen=True)
class RiskScore:
    priority: int
    anomaly: int
    confidence: int


class TransparentRiskRanker:
    """A compact, inspectable logistic-style ranker for triage, never a policy gate."""

    def score(self, finding: RawFinding, workflow: str) -> RiskScore:
        text = f"{finding.evidence} {workflow}".lower()
        sensitive_context = sum(term in text for term in ("pull_request_target", "self-hosted", "id-token", "secrets."))
        raw = SEVERITY_WEIGHT[finding.severity] + RULE_WEIGHT[finding.rule_id] + sensitive_context * 4
        priority = min(99, max(1, raw))
        rare_ref = int("@main" in finding.evidence or "@master" in finding.evidence)
        anomaly = min(98, 18 + rare_ref * 43 + (25 if "self-hosted" in text else 0) + (20 if "artifact" in text else 0))
        confidence = min(98, 78 + (8 if finding.rule_id in {"ZP003", "ZP005"} else 0))
        return RiskScore(priority=priority, anomaly=anomaly, confidence=confidence)


def posture(findings: list[RawFinding]) -> dict[str, int]:
    critical = sum(item.severity == "critical" for item in findings)
    high = sum(item.severity == "high" for item in findings)
    score = max(0, 100 - critical * 28 - high * 12)
    return {"score": score, "critical": critical, "high": high, "covered_controls": 5}
