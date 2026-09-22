import json

from data_anonymizer.cli import main


def test_check_valid_policy(tmp_path, capsys):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"fields": {"email": {"action": "redact"}}}), encoding="utf-8")
    assert main(["check", str(policy)]) == 0
    assert "Policy OK" in capsys.readouterr().out


def test_run_csv_with_json_report(tmp_path, capsys):
    source = tmp_path / "in.csv"
    target = tmp_path / "out.csv"
    policy = tmp_path / "policy.json"
    source.write_text("name,email\nExample,x@example.test\n", encoding="utf-8")
    policy.write_text(json.dumps({"fields": {"email": {"action": "redact"}}}), encoding="utf-8")
    assert main(["run", str(source), str(target), "--policy", str(policy), "--json-report"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["records"] == 1
    assert "[REDACTED]" in target.read_text(encoding="utf-8")
