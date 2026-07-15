import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
from fastapi.testclient import TestClient

from app.action_runner import run
from app.main import app
from app.remediator import deterministic_patch
from app.scanner import scan_workflow
from app.validator import validate

ROOT = Path(__file__).resolve().parents[1]


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / "fixtures" / "insecure-release.yml").read_text(encoding="utf-8")

    def test_detects_high_signal_workflow_risks(self):
        rules = {finding.rule_id for finding in scan_workflow(self.workflow)}
        self.assertTrue({"ZP001", "ZP002", "ZP003", "ZP004", "ZP005"}.issubset(rules))

    def test_remediation_only_changes_selected_safe_nodes_and_stays_valid_yaml(self):
        selected = [finding for finding in scan_workflow(self.workflow) if finding.fixable]
        patched = deterministic_patch(self.workflow, selected)
        yaml.compose(patched)
        checks = validate(self.workflow, patched, selected)
        self.assertFalse(any(check.status == "failed" for check in checks))
        self.assertIn("bash artifact/deploy.sh", patched)
        self.assertIn("ZP005", {finding.rule_id for finding in scan_workflow(patched)})

    def test_script_text_is_never_treated_as_an_action(self):
        workflow = """name: test
on: pull_request
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: 'echo "uses: actions/checkout@v4"'
"""
        self.assertNotIn("ZP001", {finding.rule_id for finding in scan_workflow(workflow)})

    def test_sequence_trigger_is_detected_and_remediated(self):
        workflow = """name: test
on: [pull_request_target, workflow_dispatch]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: echo safe
"""
        selected = [item for item in scan_workflow(workflow) if item.rule_id == "ZP003"]
        self.assertEqual(len(selected), 1)
        patched = deterministic_patch(workflow, selected)
        self.assertIn("pull_request", patched)
        self.assertNotIn("pull_request_target", patched)

    def test_artifact_execution_is_detected_across_steps(self):
        workflow = """name: test
on: pull_request
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093
      - run: node dist/app.js
"""
        finding = next(item for item in scan_workflow(workflow) if item.rule_id == "ZP005")
        self.assertFalse(finding.fixable)

    def test_permissions_and_runner_are_scoped_to_their_actual_context(self):
        workflow = """name: deploy
on: workflow_dispatch
permissions:
  contents: read
jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - run: echo write
"""
        rules = {finding.rule_id for finding in scan_workflow(workflow)}
        self.assertNotIn("ZP002", rules)
        self.assertNotIn("ZP004", rules)

    def test_runner_label_sequences_are_review_only_for_pr_workflows(self):
        workflow = """name: test
on: pull_request
jobs:
  check:
    runs-on: [self-hosted, linux, x64]
    steps:
      - run: echo safe
"""
        finding = next(item for item in scan_workflow(workflow) if item.rule_id == "ZP004")
        self.assertFalse(finding.fixable)

    def test_overlapping_replacements_are_rejected(self):
        selected = [item for item in scan_workflow(self.workflow) if item.fixable]
        with self.assertRaisesRegex(ValueError, "overlap"):
            deterministic_patch(self.workflow, [selected[0], selected[0]])


class ActionRunnerTests(unittest.TestCase):
    def test_writes_a_redacted_report_and_honors_fail_threshold(self):
        with patch("app.action_runner.Path.mkdir"), patch("app.action_runner.Path.write_text") as write_report:
            status, report = run("fixtures/insecure-release.yml", ".zeropatch/report.json", "critical", ROOT)
        saved = json.loads(write_report.call_args.args[0])
        self.assertEqual(status, 1)
        self.assertEqual(report["finding_count"], saved["finding_count"])
        self.assertNotIn("evidence", saved["findings"][0])

    def test_rejects_paths_outside_the_workspace(self):
        with self.assertRaises(ValueError):
            run("..", ".zeropatch/report.json", "never", ROOT)

    def test_report_path_write_errors_are_reported_cleanly(self):
        with patch("app.action_runner.Path.write_text", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(ValueError, "Unable to write report-path"):
                run("fixtures/insecure-release.yml", ".zeropatch/report.json", "never", ROOT)


class ApiSafetyTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_malformed_yaml_is_rejected(self):
        response = self.client.post("/api/scan", json={"workflow": "jobs: [", "source_name": "bad.yml"})
        self.assertEqual(response.status_code, 400)

    def test_unsupported_action_is_review_only_and_cannot_be_remediated(self):
        workflow = """name: test
on: pull_request
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: acme/example-action@v1
"""
        scan = self.client.post("/api/scan", json={"workflow": workflow, "source_name": "case.yml"})
        self.assertEqual(scan.status_code, 200)
        finding = scan.json()["findings"][0]
        self.assertFalse(finding["fixable"])
        remediation = self.client.post("/api/remediate", json={"workflow": workflow, "source_name": "case.yml", "finding_ids": [finding["id"]]})
        self.assertEqual(remediation.status_code, 400)

    def test_security_headers_are_present(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        for header in ("content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy"):
            self.assertIn(header, response.headers)


if __name__ == "__main__":
    unittest.main()
