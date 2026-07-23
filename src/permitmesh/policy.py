from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
from typing import Any


SUPPORTED_VERSION = "0.1"
PATH_REQUIRED_CAPABILITIES = {"read", "edit"}
KNOWN_CAPABILITIES = {
    "read",
    "edit",
    "shell",
    "test",
    "commit",
    "review",
    "deploy",
    "publish",
    "spend",
}
TOP_LEVEL_FIELDS = {
    "contract_version",
    "issuer",
    "subject",
    "scope",
    "capabilities",
    "validity",
    "limits",
    "approval_gates",
    "lifecycle",
    "validation",
    "signature",
}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    contract_digest: str
    violations: tuple[str, ...]
    checks: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def contract_digest(contract: Any) -> str:
    payload = dict(contract) if isinstance(contract, dict) else contract
    if isinstance(payload, dict):
        payload.pop("signature", None)
        payload.pop("contract_digest", None)
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _parse_time(value: Any, field: str, violations: list[str]) -> datetime | None:
    if not isinstance(value, str):
        violations.append(f"{field} must be an RFC 3339 timestamp")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        violations.append(f"{field} must be an RFC 3339 timestamp")
        return None
    if parsed.tzinfo is None:
        violations.append(f"{field} must include a timezone")
        return None
    return parsed.astimezone(timezone.utc)


def _is_safe_relative_path(value: str) -> bool:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    return (
        bool(value)
        and "\x00" not in value
        and re.match(r"^[A-Za-z]:", normalized) is None
        and not path.is_absolute()
        and ".." not in path.parts
    )


def _validate_patterns(
    patterns: Any, field: str, violations: list[str], *, allow_empty: bool = False
) -> None:
    if not isinstance(patterns, list) or (not patterns and not allow_empty):
        violations.append(f"{field} must be a non-empty array")
        return
    for index, pattern in enumerate(patterns):
        if not isinstance(pattern, str) or not _is_safe_relative_path(pattern):
            violations.append(f"{field}[{index}] must be a safe relative path pattern")


def _reject_unknown_fields(
    value: dict[str, Any], allowed: set[str], field: str, violations: list[str]
) -> None:
    for unknown in sorted(value.keys() - allowed, key=str):
        violations.append(f"{field} contains unknown field: {unknown}")


def validate_contract(contract: Any) -> tuple[str, ...]:
    violations: list[str] = []
    if not isinstance(contract, dict):
        return ("contract must be a JSON object",)

    required = {
        "contract_version",
        "issuer",
        "subject",
        "scope",
        "capabilities",
        "validity",
        "limits",
        "approval_gates",
        "lifecycle",
        "validation",
    }
    missing = sorted(required - contract.keys())
    violations.extend(f"missing required field: {field}" for field in missing)
    if missing:
        return tuple(violations)
    _reject_unknown_fields(contract, TOP_LEVEL_FIELDS, "contract", violations)

    if contract["contract_version"] != SUPPORTED_VERSION:
        violations.append(
            f"contract_version must be {SUPPORTED_VERSION!r}, got {contract['contract_version']!r}"
        )

    for field in ("issuer", "subject"):
        value = contract[field]
        if not isinstance(value, dict) or not isinstance(value.get("id"), str) or not value["id"]:
            violations.append(f"{field}.id must be a non-empty string")
        elif isinstance(value, dict):
            _reject_unknown_fields(value, {"id", "display_name"}, field, violations)

    capabilities = contract["capabilities"]
    if not isinstance(capabilities, list) or not capabilities:
        violations.append("capabilities must be a non-empty array")
    elif not all(isinstance(capability, str) for capability in capabilities):
        violations.append("capabilities must contain strings")
    else:
        unknown = sorted(set(capabilities) - KNOWN_CAPABILITIES)
        if unknown:
            violations.append(f"capabilities contains unknown values: {', '.join(unknown)}")
        if len(capabilities) != len(set(capabilities)):
            violations.append("capabilities must not contain duplicates")

    scope = contract["scope"]
    if not isinstance(scope, dict):
        violations.append("scope must be an object")
    else:
        _reject_unknown_fields(scope, {"repositories", "channels"}, "scope", violations)
        repositories = scope.get("repositories")
        if not isinstance(repositories, list) or not repositories:
            violations.append("scope.repositories must be a non-empty array")
        else:
            names: set[str] = set()
            for index, repo in enumerate(repositories):
                prefix = f"scope.repositories[{index}]"
                if not isinstance(repo, dict):
                    violations.append(f"{prefix} must be an object")
                    continue
                _reject_unknown_fields(
                    repo, {"name", "refs", "allow_paths", "deny_paths"}, prefix, violations
                )
                name = repo.get("name")
                if not isinstance(name, str) or not name:
                    violations.append(f"{prefix}.name must be a non-empty string")
                elif name in names:
                    violations.append(f"{prefix}.name duplicates repository {name!r}")
                else:
                    names.add(name)
                refs = repo.get("refs")
                if not isinstance(refs, list) or not refs or not all(
                    isinstance(ref, str) and ref for ref in refs
                ):
                    violations.append(f"{prefix}.refs must be a non-empty string array")
                elif len(refs) != len(set(refs)):
                    violations.append(f"{prefix}.refs must not contain duplicates")
                _validate_patterns(repo.get("allow_paths"), f"{prefix}.allow_paths", violations)
                _validate_patterns(
                    repo.get("deny_paths", []),
                    f"{prefix}.deny_paths",
                    violations,
                    allow_empty=True,
                )

        channels = scope.get("channels", [])
        if not isinstance(channels, list) or not all(
            isinstance(channel, str) and channel for channel in channels
        ):
            violations.append("scope.channels must be a string array")
        elif len(channels) != len(set(channels)):
            violations.append("scope.channels must not contain duplicates")

    validity = contract["validity"]
    if not isinstance(validity, dict):
        violations.append("validity must be an object")
    else:
        _reject_unknown_fields(
            validity, {"not_before", "expires_at"}, "validity", violations
        )
        not_before = _parse_time(validity.get("not_before"), "validity.not_before", violations)
        expires_at = _parse_time(validity.get("expires_at"), "validity.expires_at", violations)
        if not_before and expires_at and expires_at <= not_before:
            violations.append("validity.expires_at must be after validity.not_before")

    limits = contract["limits"]
    if not isinstance(limits, dict):
        violations.append("limits must be an object")
    else:
        _reject_unknown_fields(
            limits,
            {"max_files_changed", "max_commands", "max_cost_usd"},
            "limits",
            violations,
        )
        for field in ("max_files_changed", "max_commands"):
            value = limits.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                violations.append(f"limits.{field} must be a non-negative integer")
        cost = limits.get("max_cost_usd")
        if (
            not isinstance(cost, (int, float))
            or isinstance(cost, bool)
            or not math.isfinite(cost)
            or cost < 0
        ):
            violations.append("limits.max_cost_usd must be a finite non-negative number")

    gates = contract["approval_gates"]
    if not isinstance(gates, list):
        violations.append("approval_gates must be an array")
    else:
        for index, gate in enumerate(gates):
            prefix = f"approval_gates[{index}]"
            if not isinstance(gate, dict):
                violations.append(f"{prefix} must be an object")
                continue
            _reject_unknown_fields(
                gate, {"actions", "min_approvals", "approvers"}, prefix, violations
            )
            actions = gate.get("actions")
            if (
                not isinstance(actions, list)
                or not actions
                or not all(isinstance(action, str) for action in actions)
                or not set(actions) <= KNOWN_CAPABILITIES
            ):
                violations.append(f"{prefix}.actions must contain known capabilities")
            elif len(actions) != len(set(actions)):
                violations.append(f"{prefix}.actions must not contain duplicates")
            minimum = gate.get("min_approvals")
            if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
                violations.append(f"{prefix}.min_approvals must be a positive integer")
            approvers = gate.get("approvers")
            if not isinstance(approvers, list) or not approvers or not all(
                isinstance(approver, str) and approver for approver in approvers
            ):
                violations.append(f"{prefix}.approvers must be a non-empty string array")
            else:
                if len(approvers) != len(set(approvers)):
                    violations.append(f"{prefix}.approvers must not contain duplicates")
                if isinstance(minimum, int) and minimum > len(set(approvers)):
                    violations.append(f"{prefix}.min_approvals exceeds unique approvers")

    lifecycle = contract["lifecycle"]
    if not isinstance(lifecycle, dict):
        violations.append("lifecycle must be an object")
    else:
        _reject_unknown_fields(
            lifecycle, {"claim_id", "fencing_generation"}, "lifecycle", violations
        )
        if not isinstance(lifecycle.get("claim_id"), str) or not lifecycle["claim_id"]:
            violations.append("lifecycle.claim_id must be a non-empty string")
        generation = lifecycle.get("fencing_generation")
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
            violations.append("lifecycle.fencing_generation must be a positive integer")

    validation = contract["validation"]
    if not isinstance(validation, dict):
        violations.append("validation must be an object")
    else:
        _reject_unknown_fields(
            validation,
            {"required_commands", "required_artifacts"},
            "validation",
            violations,
        )
        for field in ("required_commands", "required_artifacts"):
            value = validation.get(field)
            if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
                violations.append(f"validation.{field} must be a string array")
            elif len(value) != len(set(value)):
                violations.append(f"validation.{field} must not contain duplicates")

    signature = contract.get("signature")
    if signature is not None:
        if not isinstance(signature, dict):
            violations.append("signature must be an object")
        else:
            _reject_unknown_fields(
                signature, {"algorithm", "public_key", "value"}, "signature", violations
            )
            for field in ("algorithm", "public_key", "value"):
                if not isinstance(signature.get(field), str) or not signature[field]:
                    violations.append(f"signature.{field} must be a non-empty string")

    return tuple(violations)


def _matches_path(path: str, pattern: str) -> bool:
    normalized_path = path.replace("\\", "/")
    normalized_pattern = pattern.replace("\\", "/")
    if normalized_pattern.endswith("/**"):
        root = normalized_pattern[:-3].rstrip("/")
        return normalized_path == root or normalized_path.startswith(f"{root}/")
    return PurePosixPath(normalized_path).match(normalized_pattern)


def authorize(
    contract: dict[str, Any],
    request: dict[str, Any],
    *,
    now: datetime | None = None,
) -> Decision:
    digest = contract_digest(contract)
    violations = list(validate_contract(contract))
    checks: list[str] = []
    if violations:
        return Decision(False, digest, tuple(violations), tuple(checks))
    if not isinstance(request, dict):
        return Decision(False, digest, ("request must be a JSON object",), tuple(checks))
    request_fields = {
        "subject_id",
        "action",
        "channel",
        "repository",
        "ref",
        "path",
        "files_changed",
        "commands_used",
        "cost_usd",
        "claim_id",
        "fencing_generation",
        "approvals",
        "at",
    }
    _reject_unknown_fields(request, request_fields, "request", violations)
    required_request_fields = request_fields - {"path", "at", "channel"}
    for field in sorted(required_request_fields - request.keys()):
        violations.append(f"missing required request field: {field}")

    # The evaluator's clock is authoritative. A request's self-declared time is
    # parsed for receipt quality but can never extend or revive authorization.
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    requested_at = request.get("at")
    if requested_at is not None:
        _parse_time(requested_at, "request.at", violations)
    not_before = _parse_time(contract["validity"]["not_before"], "validity.not_before", violations)
    expires_at = _parse_time(contract["validity"]["expires_at"], "validity.expires_at", violations)
    if not_before and effective_now < not_before:
        violations.append("contract is not active yet")
    if expires_at and effective_now >= expires_at:
        violations.append("contract has expired")
    checks.append("validity_window")

    if request.get("subject_id") != contract["subject"]["id"]:
        violations.append("subject_id does not match the active contract")
    checks.append("subject")

    configured_channels = contract["scope"]["channels"]
    requested_channel = request.get("channel")
    if configured_channels and requested_channel not in configured_channels:
        violations.append(f"channel {requested_channel!r} is outside scope")
    checks.append("channel")

    action = request.get("action")
    if action not in contract["capabilities"]:
        violations.append(f"capability {action!r} is not granted")
    if action in PATH_REQUIRED_CAPABILITIES and request.get("path") is None:
        violations.append(f"request.path is required for {action}")
    checks.append("capability")

    repository_name = request.get("repository")
    repository = next(
        (
            candidate
            for candidate in contract["scope"]["repositories"]
            if candidate["name"] == repository_name
        ),
        None,
    )
    if repository is None:
        violations.append(f"repository {repository_name!r} is outside scope")
    else:
        requested_ref = request.get("ref")
        if not isinstance(requested_ref, str) or not any(
            fnmatchcase(requested_ref, pattern) for pattern in repository["refs"]
        ):
            violations.append(f"ref {requested_ref!r} is outside scope")

        requested_path = request.get("path")
        if requested_path is not None:
            if not isinstance(requested_path, str) or not _is_safe_relative_path(requested_path):
                violations.append("request.path must be a safe relative path")
            else:
                denied = any(
                    _matches_path(requested_path, pattern)
                    for pattern in repository.get("deny_paths", [])
                )
                allowed = any(
                    _matches_path(requested_path, pattern)
                    for pattern in repository["allow_paths"]
                )
                if denied:
                    violations.append(f"path {requested_path!r} matches a deny rule")
                elif not allowed:
                    violations.append(f"path {requested_path!r} is outside allowed paths")
    checks.append("repository_ref_path")

    limits = contract["limits"]
    request_limits = {
        "files_changed": ("max_files_changed", int),
        "commands_used": ("max_commands", int),
        "cost_usd": ("max_cost_usd", (int, float)),
    }
    for request_field, (limit_field, expected_type) in request_limits.items():
        value = request.get(request_field, 0)
        if (
            not isinstance(value, expected_type)
            or isinstance(value, bool)
            or (isinstance(value, float) and not math.isfinite(value))
            or value < 0
        ):
            violations.append(
                f"request.{request_field} must be a finite non-negative number"
            )
        elif value > limits[limit_field]:
            violations.append(
                f"request.{request_field}={value} exceeds {limit_field}={limits[limit_field]}"
            )
    checks.append("budgets")

    lifecycle = contract["lifecycle"]
    if request.get("claim_id") != lifecycle["claim_id"]:
        violations.append("claim_id does not match the active contract")
    if request.get("fencing_generation") != lifecycle["fencing_generation"]:
        violations.append("fencing_generation does not match the active contract")
    checks.append("claim_and_fence")

    raw_approvals = request.get("approvals")
    if not isinstance(raw_approvals, list) or not all(
        isinstance(approval, str) and approval for approval in raw_approvals
    ):
        violations.append("request.approvals must be a string array")
        supplied_approvals: set[str] = set()
    else:
        if len(raw_approvals) != len(set(raw_approvals)):
            violations.append("request.approvals must not contain duplicates")
        supplied_approvals = set(raw_approvals)
    for gate in contract["approval_gates"]:
        if action in gate["actions"]:
            qualified = supplied_approvals.intersection(gate["approvers"])
            if len(qualified) < gate["min_approvals"]:
                violations.append(
                    f"action {action!r} requires {gate['min_approvals']} approval(s) "
                    f"from the configured approvers"
                )
    checks.append("approval_gates")

    return Decision(not violations, digest, tuple(violations), tuple(checks))


def verify_completion(
    contract: dict[str, Any],
    report: dict[str, Any],
    *,
    now: datetime | None = None,
) -> Decision:
    digest = contract_digest(contract)
    violations = list(validate_contract(contract))
    checks: list[str] = []
    if violations:
        return Decision(False, digest, tuple(violations), tuple(checks))
    if not isinstance(report, dict):
        return Decision(False, digest, ("completion report must be a JSON object",), ())

    report_fields = {
        "subject_id",
        "claim_id",
        "fencing_generation",
        "commands_passed",
        "artifacts_present",
    }
    _reject_unknown_fields(report, report_fields, "completion report", violations)
    for field in sorted(report_fields - report.keys()):
        violations.append(f"missing required completion field: {field}")

    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    not_before = _parse_time(contract["validity"]["not_before"], "validity.not_before", violations)
    expires_at = _parse_time(contract["validity"]["expires_at"], "validity.expires_at", violations)
    if not_before and effective_now < not_before:
        violations.append("contract is not active yet")
    if expires_at and effective_now >= expires_at:
        violations.append("contract has expired")
    checks.append("validity_window")

    if report.get("subject_id") != contract["subject"]["id"]:
        violations.append("subject_id does not match the active contract")
    checks.append("subject")

    lifecycle = contract["lifecycle"]
    if report.get("claim_id") != lifecycle["claim_id"]:
        violations.append("claim_id does not match the active contract")
    if report.get("fencing_generation") != lifecycle["fencing_generation"]:
        violations.append("fencing_generation does not match the active contract")
    checks.append("claim_and_fence")

    evidence_fields = {
        "commands_passed": "required_commands",
        "artifacts_present": "required_artifacts",
    }
    for report_field, contract_field in evidence_fields.items():
        supplied = report.get(report_field)
        if not isinstance(supplied, list) or not all(
            isinstance(item, str) and item for item in supplied
        ):
            violations.append(f"completion report.{report_field} must be a string array")
            supplied_set: set[str] = set()
        else:
            supplied_set = set(supplied)
            if len(supplied) != len(supplied_set):
                violations.append(
                    f"completion report.{report_field} must not contain duplicates"
                )
        for missing in sorted(
            set(contract["validation"][contract_field]) - supplied_set
        ):
            violations.append(f"missing {contract_field}: {missing}")
        checks.append(contract_field)

    return Decision(not violations, digest, tuple(violations), tuple(checks))


def to_nostr_event_template(
    contract: dict[str, Any], *, created_at: int | None = None
) -> dict[str, Any]:
    violations = validate_contract(contract)
    if violations:
        raise ValueError("; ".join(violations))
    for principal in ("issuer", "subject"):
        identifier = contract[principal]["id"]
        if re.fullmatch(r"[0-9a-f]{64}", identifier) is None:
            raise ValueError(
                f"{principal}.id must be a 64-character lowercase hex Nostr public key"
            )
    digest = contract_digest(contract)
    return {
        "status": "unsigned_template",
        "instruction": "Compute the NIP-01 id and signature with the issuer's Nostr key before publishing.",
        "event": {
            "kind": 30078,
            "created_at": int(created_at or datetime.now(timezone.utc).timestamp()),
            "tags": [
                ["d", f"permitmesh:contract:{digest}"],
                ["t", "permitmesh"],
                ["p", contract["subject"]["id"]],
                ["x", digest],
            ],
            "content": canonical_json(contract),
            "pubkey": contract["issuer"]["id"],
            "id": "",
            "sig": "",
        },
    }
