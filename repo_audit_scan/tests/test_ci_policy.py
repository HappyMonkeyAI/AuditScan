from pathlib import Path
import yaml

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "external-content-gate.yml"


def test_external_gate_workflow_uses_immutable_action_refs():
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    for step in data["jobs"]["audit"]["steps"]:
        if "uses" in step:
            assert "@" in step["uses"]
            ref = step["uses"].rsplit("@", 1)[1]
            assert len(ref) == 40 and all(c in "0123456789abcdef" for c in ref.lower())


def test_external_gate_workflow_has_no_secret_for_pull_requests():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "pull_request:" in text
    assert "secrets." not in text
    assert "if: always()" in text
    assert "external-content-audit" in text
