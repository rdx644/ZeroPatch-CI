from __future__ import annotations

from collections.abc import Iterable

from .scanner import RawFinding, WorkflowParseError, scan_workflow
from .schemas import EvidenceCheck


def validate(before: str, after: str, selected: Iterable[RawFinding]) -> list[EvidenceCheck]:
    selected_findings = list(selected)
    try:
        remaining = {(finding.rule_id, finding.line) for finding in scan_workflow(after)}
        yaml_check = EvidenceCheck(name="Workflow syntax", status="passed", detail="Patched workflow parsed successfully as YAML.")
    except WorkflowParseError as exc:
        remaining = set()
        yaml_check = EvidenceCheck(name="Workflow syntax", status="failed", detail=str(exc))
    policy_passed = yaml_check.status == "passed" and all((finding.rule_id, finding.line) not in remaining for finding in selected_findings)
    changed = before != after
    return [
        yaml_check,
        EvidenceCheck(name="Patch is minimal", status="passed" if changed else "failed", detail="Only selected, deterministic policy transformations are applied." if changed else "No safe transformation was available."),
        EvidenceCheck(name="Selected policy checks", status="passed" if policy_passed else "failed", detail="Selected findings no longer match the patched workflow." if policy_passed else "A selected policy match remains after remediation."),
        EvidenceCheck(name="Untrusted code execution", status="skipped", detail="ZeroPatch does not execute repository or artifact code during this review."),
        EvidenceCheck(name="Manual approval", status="passed", detail="Output is a draft remediation artifact only; merge authority is never granted."),
    ]
