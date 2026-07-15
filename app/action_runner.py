"""GitHub Action entry point for static, non-executing workflow checks."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .scanner import WorkflowParseError, scan_workflow

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
WORKFLOW_SUFFIXES = {".yml", ".yaml"}
MAX_WORKFLOW_BYTES = 1_000_000


def _workspace() -> Path:
    return Path(os.getenv("GITHUB_WORKSPACE", Path.cwd())).resolve()


def _inside_workspace(workspace: Path, value: str) -> Path:
    candidate = (workspace / value).resolve() if not Path(value).is_absolute() else Path(value).resolve()
    if candidate != workspace and workspace not in candidate.parents:
        raise ValueError("Paths must stay inside GITHUB_WORKSPACE.")
    return candidate


def _workflow_files(workspace: Path, value: str) -> list[Path]:
    target = _inside_workspace(workspace, value)
    if target.is_file():
        if target.suffix.lower() not in WORKFLOW_SUFFIXES:
            raise ValueError("workflow-path must point to a .yml or .yaml file.")
        return [target]
    if not target.is_dir():
        raise ValueError("workflow-path does not exist.")
    files = [path.resolve() for path in target.rglob("*") if path.is_file() and path.suffix.lower() in WORKFLOW_SUFFIXES]
    return sorted(path for path in files if path == workspace or workspace in path.parents)


def _write_github_output(values: dict[str, str]) -> None:
    output_file = os.getenv("GITHUB_OUTPUT")
    if not output_file:
        return
    with Path(output_file).open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def _write_summary(report: dict[str, object]) -> None:
    summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return
    with Path(summary_file).open("a", encoding="utf-8") as handle:
        handle.write("## ZeroPatch CI\n\n")
        handle.write(f"- Workflows scanned: {report['scanned_files']}\n")
        handle.write(f"- Findings: {report['finding_count']}\n")
        handle.write(f"- Blocking findings: {report['blocking_count']}\n")
        handle.write(f"- Parse errors: {len(report['errors'])}\n")


def run(workflow_path: str, report_path: str, fail_on: str, workspace: Path | None = None) -> tuple[int, dict[str, object]]:
    if fail_on not in {"never", *SEVERITY_RANK}:
        raise ValueError("fail-on must be one of never, critical, high, medium, or low.")
    workspace = (workspace or _workspace()).resolve()
    files = _workflow_files(workspace, workflow_path)
    if not files:
        raise ValueError("No .yml or .yaml workflow files were found.")
    findings: list[dict[str, object]] = []
    errors: list[dict[str, str]] = []
    for workflow in files:
        relative = workflow.relative_to(workspace).as_posix()
        try:
            if workflow.stat().st_size > MAX_WORKFLOW_BYTES:
                raise ValueError(f"Workflow exceeds the {MAX_WORKFLOW_BYTES:,}-byte scan limit.")
            for finding in scan_workflow(workflow.read_text(encoding="utf-8")):
                findings.append({
                    "file": relative,
                    "rule_id": finding.rule_id,
                    "severity": finding.severity,
                    "line": finding.line,
                    "title": finding.title,
                    "recommendation": finding.recommendation,
                    "fixable": finding.fixable,
                })
        except (OSError, UnicodeError, ValueError, WorkflowParseError) as exc:
            errors.append({"file": relative, "error": str(exc)})

    threshold = SEVERITY_RANK.get(fail_on, 5)
    blocking = [finding for finding in findings if SEVERITY_RANK[finding["severity"]] >= threshold]
    report: dict[str, object] = {
        "schema_version": 1,
        "scanned_files": len(files),
        "finding_count": len(findings),
        "blocking_count": len(blocking),
        "findings": findings,
        "errors": errors,
    }
    report_target = _inside_workspace(workspace, report_path)
    try:
        report_target.parent.mkdir(parents=True, exist_ok=True)
        report_target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Unable to write report-path: {exc}") from exc
    _write_github_output({
        "report-path": report_target.relative_to(workspace).as_posix(),
        "finding-count": str(len(findings)),
        "blocking-findings": str(len(blocking)),
    })
    _write_summary(report)
    if errors:
        return 2, report
    return (1 if blocking else 0), report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Statically scan GitHub Actions workflows without executing them.")
    parser.add_argument("--workflow-path", default=".github/workflows")
    parser.add_argument("--report-path", default=".zeropatch/zeropatch-report.json")
    parser.add_argument("--fail-on", choices=("never", "critical", "high", "medium", "low"), default="critical")
    args = parser.parse_args(argv)
    try:
        status, report = run(args.workflow_path, args.report_path, args.fail_on)
    except ValueError as exc:
        print(f"ZeroPatch input error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({key: report[key] for key in ("scanned_files", "finding_count", "blocking_count", "errors")}, sort_keys=True))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
