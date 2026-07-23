from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any

from .policy import authorize, contract_digest, to_nostr_event_template, validate_contract


def _load_json(path: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read {path!r}: {exc}") from exc


def _emit(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _evaluation_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("must include a timezone")
    return parsed.astimezone(timezone.utc)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="permitmesh",
        description="Validate capability contracts and authorize agent actions.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate one contract.")
    validate_parser.add_argument("contract")

    digest_parser = subparsers.add_parser("digest", help="Print the canonical contract digest.")
    digest_parser.add_argument("contract")

    authorize_parser = subparsers.add_parser(
        "authorize", help="Evaluate one action request against a contract."
    )
    authorize_parser.add_argument("contract")
    authorize_parser.add_argument("request")
    authorize_parser.add_argument(
        "--evaluation-time",
        type=_evaluation_time,
        help="Trusted evaluator time override for deterministic tests and replay.",
    )

    event_parser = subparsers.add_parser(
        "to-event", help="Create an unsigned Nostr application-data event template."
    )
    event_parser.add_argument("contract")
    event_parser.add_argument("--created-at", type=int)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        contract = _load_json(args.contract)
        if not isinstance(contract, dict):
            raise ValueError("contract must be a JSON object")

        if args.command == "validate":
            violations = validate_contract(contract)
            _emit(
                {
                    "valid": not violations,
                    "contract_digest": contract_digest(contract),
                    "violations": violations,
                }
            )
            return 0 if not violations else 2

        if args.command == "digest":
            print(contract_digest(contract))
            return 0

        if args.command == "authorize":
            request = _load_json(args.request)
            decision = authorize(contract, request, now=args.evaluation_time)
            _emit(decision.to_dict())
            return 0 if decision.allowed else 3

        if args.command == "to-event":
            _emit(to_nostr_event_template(contract, created_at=args.created_at))
            return 0

    except ValueError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    return 1
