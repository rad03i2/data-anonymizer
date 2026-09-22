from __future__ import annotations

import csv
import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


class AnonymizationError(ValueError):
    """Raised when a policy or input cannot be processed safely."""


@dataclass(frozen=True)
class Report:
    records: int
    fields_changed: int
    rules_applied: dict[str, int]

    def as_dict(self) -> dict[str, Any]:
        return {"records": self.records, "fields_changed": self.fields_changed, "rules_applied": self.rules_applied}


def load_policy(path: str | Path) -> dict[str, dict[str, Any]]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnonymizationError(f"Cannot load policy: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("fields"), dict):
        raise AnonymizationError("Policy must contain an object named 'fields'.")
    allowed = {"redact", "mask", "hmac", "generalize_number", "keep"}
    for field, rule in raw["fields"].items():
        if not isinstance(field, str) or not isinstance(rule, dict) or rule.get("action") not in allowed:
            raise AnonymizationError(f"Invalid rule for field {field!r}.")
        if rule["action"] == "generalize_number":
            bucket = rule.get("bucket")
            if not isinstance(bucket, (int, float)) or isinstance(bucket, bool) or bucket <= 0:
                raise AnonymizationError(f"Field {field!r} requires a positive numeric bucket.")
    return raw["fields"]


def _transform(value: Any, rule: Mapping[str, Any], key: bytes | None) -> Any:
    action = rule["action"]
    if action == "keep" or value is None:
        return value
    if action == "redact":
        return rule.get("replacement", "[REDACTED]")
    text = str(value)
    if action == "mask":
        visible = int(rule.get("visible", 4))
        if visible < 0:
            raise AnonymizationError("mask.visible cannot be negative.")
        if not text:
            return text
        if visible == 0:
            return "*" * len(text)
        return "*" * max(0, len(text) - visible) + text[-visible:]
    if action == "hmac":
        if not key:
            raise AnonymizationError("HMAC rules require a non-empty secret key.")
        length = int(rule.get("length", 16))
        if not 8 <= length <= 64:
            raise AnonymizationError("hmac.length must be between 8 and 64.")
        digest = hmac.new(key, text.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"anon_{digest[:length]}"
    if action == "generalize_number":
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise AnonymizationError(f"Expected a number, got {value!r}.") from exc
        bucket = float(rule["bucket"])
        low = (number // bucket) * bucket
        high = low + bucket
        def fmt(n: float) -> str:
            return str(int(n)) if n.is_integer() else f"{n:g}"
        return f"{fmt(low)}-{fmt(high)}"
    raise AnonymizationError(f"Unsupported action: {action}")


def anonymize_records(records: Iterable[Mapping[str, Any]], rules: Mapping[str, Mapping[str, Any]], *, key: bytes | None = None, strict: bool = False) -> tuple[list[dict[str, Any]], Report]:
    output: list[dict[str, Any]] = []
    counts: dict[str, int] = {name: 0 for name in rules}
    changed = 0
    for index, record in enumerate(records, start=1):
        if not isinstance(record, Mapping):
            raise AnonymizationError(f"Record {index} is not an object.")
        row = dict(record)
        if strict:
            missing = [name for name in rules if name not in row]
            if missing:
                raise AnonymizationError(f"Record {index} is missing fields: {', '.join(missing)}")
        for field, rule in rules.items():
            if field not in row:
                continue
            old = row[field]
            new = _transform(old, rule, key)
            row[field] = new
            counts[field] += 1
            if new != old:
                changed += 1
        output.append(row)
    return output, Report(len(output), changed, counts)


def read_records(path: str | Path) -> tuple[list[dict[str, Any]], str, list[str]]:
    source = Path(path)
    suffix = source.suffix.lower()
    try:
        if suffix == ".json":
            data = json.loads(source.read_text(encoding="utf-8-sig"))
            if not isinstance(data, list):
                raise AnonymizationError("JSON input must be a top-level array of objects.")
            records = [dict(item) if isinstance(item, dict) else item for item in data]
            fields = list(dict.fromkeys(k for item in records if isinstance(item, dict) for k in item))
            return records, "json", fields
        if suffix == ".csv":
            with source.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                if not reader.fieldnames:
                    raise AnonymizationError("CSV input requires a header row.")
                return list(reader), "csv", list(reader.fieldnames)
    except (OSError, json.JSONDecodeError, csv.Error) as exc:
        raise AnonymizationError(f"Cannot read input: {exc}") from exc
    raise AnonymizationError("Input must use .csv or .json extension.")


def write_records(path: str | Path, records: list[dict[str, Any]], fmt: str, fields: list[str]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        target.write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)


def anonymize_file(input_path: str | Path, output_path: str | Path, policy_path: str | Path, *, key: bytes | None = None, strict: bool = False) -> Report:
    source, target = Path(input_path).resolve(), Path(output_path).resolve()
    if source == target:
        raise AnonymizationError("Refusing to overwrite the source file.")
    rules = load_policy(policy_path)
    records, fmt, fields = read_records(source)
    transformed, report = anonymize_records(records, rules, key=key, strict=strict)
    if fmt == "json":
        fields = list(dict.fromkeys(k for row in transformed for k in row))
    write_records(target, transformed, fmt, fields)
    return report
