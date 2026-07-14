"""Focused behavioral evals for the real ZeroPatch scan path."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.main import build_response


def main():
    workflow = (ROOT / "fixtures" / "insecure-release.yml").read_text(encoding="utf-8")
    result = build_response(workflow, "insecure-release.yml")
    rules = {finding.rule_id for finding in result.findings}
    cases = [json.loads(line) for line in (ROOT / "evals" / "cases.jsonl").read_text(encoding="utf-8").splitlines()]
    outcomes = []
    for case in cases:
        if "expected_rules" in case:
            passed = set(case["expected_rules"]).issubset(rules)
        else:
            passed = any(item.rule_id == case["expected_non_fixable"] and not item.fixable for item in result.findings)
        outcomes.append({"name": case["name"], "passed": passed})
    if not all(item["passed"] for item in outcomes):
        raise SystemExit(1)
    payload = json.dumps(outcomes, indent=2)
    try:
        output_dir = ROOT / "evals" / "results"
        output_dir.mkdir(exist_ok=True)
        (output_dir / "latest.json").write_text(payload, encoding="utf-8")
    except PermissionError:
        print("Evaluation results could not be persisted; returning verified results on stdout.", file=sys.stderr)
    print(payload)


if __name__ == "__main__":
    main()
