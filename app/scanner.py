from __future__ import annotations

import re
from dataclasses import dataclass

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


APPROVED_ACTION_PINS = {
    "actions/checkout": "11bd71901bbe5b1630ceea73d27597364c9af683",
    "actions/setup-node": "1e60f620b9541dce1d90b59bbf1b299ec45b75cf",
    "actions/upload-artifact": "65462800fd760344b1a7b4382951275a0abb4808",
    "actions/download-artifact": "d3f86a106a0bac45b974a628896c90dbdf5c8093",
}

RULES = {
    "ZP001": ("Unpinned GitHub Action", "high", "Pin approved actions to a full commit SHA."),
    "ZP002": ("Excessive workflow token permission", "high", "Use the least-privileged permission, usually contents: read."),
    "ZP003": ("Unsafe pull_request_target trigger", "critical", "Use pull_request or isolate trusted metadata-only work."),
    "ZP004": ("Self-hosted runner exposure", "high", "Use a GitHub-hosted runner for code from pull requests."),
    "ZP005": ("Untrusted artifact execution", "critical", "Never execute artifacts produced by an untrusted pull request."),
}

SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
EXECUTION = re.compile(r"(?:^|\s)(?:\./[^\s]+|bash\s+|sh\s+|node\s+|python(?:3)?\s+|pwsh\s+|powershell\s+)")


class WorkflowParseError(ValueError):
    """Raised when the supplied text is not a mapping-shaped YAML workflow."""


@dataclass(frozen=True)
class RawFinding:
    rule_id: str
    title: str
    severity: str
    line: int
    evidence: str
    recommendation: str
    fixable: bool = False
    start: int = 0
    end: int = 0
    replacement: str | None = None


def _parse(workflow: str) -> MappingNode:
    try:
        root = yaml.compose(workflow)
    except yaml.YAMLError as exc:
        raise WorkflowParseError(f"Workflow must be valid YAML: {exc.problem or 'parse error'}") from exc
    if not isinstance(root, MappingNode):
        raise WorkflowParseError("Workflow must be a top-level YAML mapping.")
    return root


def _items(node: Node | None) -> list[tuple[ScalarNode, Node]]:
    if not isinstance(node, MappingNode):
        return []
    return [(key, value) for key, value in node.value if isinstance(key, ScalarNode)]


def _get(node: Node | None, name: str) -> Node | None:
    return next((value for key, value in _items(node) if key.value == name), None)


def _finding(rule_id: str, node: Node, evidence: str, *, fixable: bool = False, replacement: str | None = None) -> RawFinding:
    title, severity, recommendation = RULES[rule_id]
    return RawFinding(rule_id, title, severity, node.start_mark.line + 1, evidence, recommendation, fixable, node.start_mark.index, node.end_mark.index, replacement)


def _trigger_names(node: Node | None) -> set[str]:
    if isinstance(node, ScalarNode):
        return {node.value}
    if isinstance(node, SequenceNode):
        return {item.value for item in node.value if isinstance(item, ScalarNode)}
    return {key.value for key, _ in _items(node)}


def _action_reference(node: Node | None) -> tuple[str, str] | None:
    if not isinstance(node, ScalarNode) or "@" not in node.value:
        return None
    action, ref = node.value.rsplit("@", 1)
    if not action or not ref or action.startswith(("./", "docker://")):
        return None
    return action, ref


def _permission_findings(node: Node | None) -> list[RawFinding]:
    findings: list[RawFinding] = []
    if isinstance(node, ScalarNode) and node.value == "write-all":
        findings.append(_finding("ZP002", node, node.value, fixable=True, replacement="{ contents: read }"))
    for key, value in _items(node):
        if isinstance(value, ScalarNode) and value.value == "write":
            findings.append(_finding("ZP002", value, f"{key.value}: {value.value}", fixable=True, replacement="read"))
    return findings


def _runner_finding(node: Node | None, untrusted_pr_path: bool) -> RawFinding | None:
    """Flag self-hosted labels for pull-request workflows without guessing a safe rewrite."""
    if not untrusted_pr_path:
        return None
    if isinstance(node, ScalarNode) and "self-hosted" in node.value:
        can_replace = node.value.strip() == "self-hosted"
        return _finding("ZP004", node, node.value, fixable=can_replace, replacement="ubuntu-latest" if can_replace else None)
    if isinstance(node, SequenceNode):
        for label in node.value:
            if isinstance(label, ScalarNode) and label.value == "self-hosted":
                return _finding("ZP004", label, label.value)
    return None

def _artifact_execution_findings(steps: Node | None) -> list[RawFinding]:
    if not isinstance(steps, SequenceNode):
        return []
    downloaded_artifact = False
    findings: list[RawFinding] = []
    for step in steps.value:
        if not isinstance(step, MappingNode):
            continue
        action_ref = _action_reference(_get(step, "uses"))
        if action_ref and action_ref[0] == "actions/download-artifact":
            downloaded_artifact = True
        run = _get(step, "run")
        if downloaded_artifact and isinstance(run, ScalarNode) and EXECUTION.search(run.value):
            findings.append(_finding("ZP005", run, run.value))
    return findings


def scan_workflow(workflow: str) -> list[RawFinding]:
    """Find policy issues using YAML node positions, never raw text heuristics."""
    root = _parse(workflow)
    findings: list[RawFinding] = []
    triggers = _trigger_names(_get(root, "on"))
    trigger_node = _get(root, "on")
    if "pull_request_target" in triggers and trigger_node is not None:
        if isinstance(trigger_node, ScalarNode):
            findings.append(_finding("ZP003", trigger_node, trigger_node.value, fixable=True, replacement="pull_request"))
        elif isinstance(trigger_node, SequenceNode):
            for item in trigger_node.value:
                if isinstance(item, ScalarNode) and item.value == "pull_request_target":
                    findings.append(_finding("ZP003", item, item.value, fixable=True, replacement="pull_request"))
        else:
            for key, _ in _items(trigger_node):
                if key.value == "pull_request_target":
                    findings.append(_finding("ZP003", key, key.value, fixable=True, replacement="pull_request"))

    findings.extend(_permission_findings(_get(root, "permissions")))
    untrusted_pr_path = bool({"pull_request", "pull_request_target"} & triggers)
    for _, job in _items(_get(root, "jobs")):
        findings.extend(_permission_findings(_get(job, "permissions")))
        runner_finding = _runner_finding(_get(job, "runs-on"), untrusted_pr_path)
        if runner_finding:
            findings.append(runner_finding)
        steps = _get(job, "steps")
        if isinstance(steps, SequenceNode):
            for step in steps.value:
                if not isinstance(step, MappingNode):
                    continue
                uses = _get(step, "uses")
                action_ref = _action_reference(uses)
                if action_ref and isinstance(uses, ScalarNode):
                    action, ref = action_ref
                    if not SHA.fullmatch(ref):
                        pin = APPROVED_ACTION_PINS.get(action)
                        findings.append(_finding("ZP001", uses, uses.value, fixable=pin is not None, replacement=f"{action}@{pin}" if pin else None))
            findings.extend(_artifact_execution_findings(steps))
    return _dedupe(findings)


def _dedupe(findings: list[RawFinding]) -> list[RawFinding]:
    seen: set[tuple[str, int, str]] = set()
    result: list[RawFinding] = []
    for finding in findings:
        key = (finding.rule_id, finding.line, finding.evidence)
        if key not in seen:
            result.append(finding)
            seen.add(key)
    return result
