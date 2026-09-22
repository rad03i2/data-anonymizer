import json
from pathlib import Path

import pytest

from data_anonymizer import AnonymizationError, anonymize_file, anonymize_records


def test_actions_are_applied_and_hmac_is_deterministic():
    rules = {
        "name": {"action": "hmac", "length": 12},
        "phone": {"action": "mask", "visible": 2},
        "age": {"action": "generalize_number", "bucket": 10},
        "note": {"action": "redact"},
    }
    rows = [{"name": "Alice", "phone": "123456", "age": 27, "note": "private"}] * 2
    result, report = anonymize_records(rows, rules, key=b"test-key")
    assert result[0]["name"] == result[1]["name"]
    assert result[0]["name"].startswith("anon_")
    assert result[0]["phone"] == "****56"
    assert result[0]["age"] == "20-30"
    assert result[0]["note"] == "[REDACTED]"
    assert report.records == 2
    assert report.fields_changed == 8


def test_hmac_requires_key():
    with pytest.raises(AnonymizationError, match="secret key"):
        anonymize_records([{"id": "x"}], {"id": {"action": "hmac"}})


def test_strict_rejects_missing_fields():
    with pytest.raises(AnonymizationError, match="missing fields"):
        anonymize_records([{"a": 1}], {"b": {"action": "redact"}}, strict=True)


def test_json_file_end_to_end(tmp_path: Path):
    source = tmp_path / "input.json"
    target = tmp_path / "output.json"
    policy = tmp_path / "policy.json"
    source.write_text(json.dumps([{"email": "a@example.test", "city": "Mosul"}]), encoding="utf-8")
    policy.write_text(json.dumps({"fields": {"email": {"action": "hmac"}}}), encoding="utf-8")
    report = anonymize_file(source, target, policy, key=b"key")
    output = json.loads(target.read_text(encoding="utf-8"))
    assert output[0]["email"].startswith("anon_")
    assert output[0]["city"] == "Mosul"
    assert report.records == 1


def test_refuses_source_overwrite(tmp_path: Path):
    source = tmp_path / "data.json"
    policy = tmp_path / "policy.json"
    source.write_text("[]", encoding="utf-8")
    policy.write_text('{"fields": {}}', encoding="utf-8")
    with pytest.raises(AnonymizationError, match="overwrite"):
        anonymize_file(source, source, policy)
