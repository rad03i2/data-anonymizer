from __future__ import annotations

import argparse
import json
import os
import sys

from .core import AnonymizationError, anonymize_file, load_policy

VERSION = "1.0.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="data-anonymizer", description="Anonymize CSV/JSON data locally using an explicit policy.")
    parser.add_argument("--version", action="version", version=f"data-anonymizer {VERSION} — Radwan Abdulhadi Ahmed / @rad03i2")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="Validate a policy without processing data")
    check.add_argument("policy")
    run = sub.add_parser("run", help="Anonymize a CSV or JSON file")
    run.add_argument("input")
    run.add_argument("output")
    run.add_argument("--policy", required=True)
    run.add_argument("--key-env", default="DATA_ANONYMIZER_KEY", help="Environment variable containing the HMAC key")
    run.add_argument("--strict", action="store_true", help="Require every configured field in every record")
    run.add_argument("--json-report", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "check":
            rules = load_policy(args.policy)
            print(f"Policy OK: {len(rules)} field rule(s)")
            return 0
        key_text = os.environ.get(args.key_env)
        key = key_text.encode("utf-8") if key_text else None
        report = anonymize_file(args.input, args.output, args.policy, key=key, strict=args.strict)
        if args.json_report:
            print(json.dumps(report.as_dict(), sort_keys=True))
        else:
            print(f"Anonymized {report.records} record(s); changed {report.fields_changed} field value(s).")
        return 0
    except AnonymizationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
