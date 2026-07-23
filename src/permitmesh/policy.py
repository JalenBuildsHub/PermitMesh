from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from decimal import Decimal
from fnmatch import fnmatchcase
import hashlib
import json
import math
import re
from typing import Any


SUPPORTED_VERSION = "0.2"
IMPLEMENTATION_VERSION = "0.2.0"
PATH_REQUIRED_CAPABILITIES = {"read", "edit"}
HIGH_RISK_CAPABILITIES = {"shell", "test", "commit", "deploy", "publish", "spend"}
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
    "operation_constraints",
    "lifecycle",
    "validation",
    "signature",
}
RFC3339_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
WINDOWS_RESERVED_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
WINDOWS_SHORT_NAME_PATTERN = re.compile(r"~[1-9][0-9]*(?:\.|$)", re.IGNORECASE)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    contract_digest: str
    violations: tuple[str, ...]
    checks: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("canonical JSON numbers must be finite")
        if value.is_zero():
            return "0"
        sign, raw_digits, exponent = value.as_tuple()
        if not isinstance(exponent, int):
            raise ValueError("canonical JSON numbers must be finite")
        digits = "".join(str(digit) for digit in raw_digits)
        while len(digits) > 1 and digits.endswith("0"):
            digits = digits[:-1]
            exponent += 1
        adjusted_exponent = len(digits) + exponent - 1
        if -6 <= adjusted_exponent < 21:
            point = len(digits) + exponent
            if point <= 0:
                number = "0." + ("0" * -point) + digits
            elif point >= len(digits):
                number = digits + ("0" * (point - len(digits)))
            else:
                number = digits[:point] + "." + digits[point:]
        else:
            mantissa = digits[0]
            if len(digits) > 1:
                mantissa += "." + digits[1:]
            exponent_sign = "+" if adjusted_exponent >= 0 else ""
            number = f"{mantissa}e{exponent_sign}{adjusted_exponent}"
        return ("-" if sign else "") + number
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("canonical JSON numbers must be finite")
        return canonical_json(Decimal(str(value)))
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("canonical JSON object keys must be strings")
        return (
            "{"
            + ",".join(
                f"{canonical_json(key)}:{canonical_json(value[key])}"
                for key in sorted(value)
            )
            + "}"
        )
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def contract_digest(contract: Any) -> str:
    payload = dict(contract) if isinstance(contract, dict) else contract
    if isinstance(payload, dict):
        payload.pop("signature", None)
        payload.pop("contract_digest", None)
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def operation_digest(action: str, operation: dict[str, Any]) -> str:
    """Bind a capability name to the exact canonical tool-and-arguments envelope."""
    payload = {"action": action, "operation": operation}
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _parse_time(value: Any, field: str, violations: list[str]) -> datetime | None:
    if not isinstance(value, str) or RFC3339_PATTERN.fullmatch(value) is None:
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
    parts = normalized.split("/")
    return (
        bool(value)
        and "\x00" not in value
        and re.match(r"^[A-Za-z]:", normalized) is None
        and not normalized.startswith("/")
        and all(part not in {"", ".", ".."} for part in parts)
        and all(":" not in part for part in parts)
        and all(not part.endswith((".", " ")) for part in parts)
        and all(WINDOWS_SHORT_NAME_PATTERN.search(part) is None for part in parts)
        and all(
            part.split(".", 1)[0].casefold() not in WINDOWS_RESERVED_NAMES
            for part in parts
        )
    )


def _validate_patterns(
    patterns: Any, field: str, violations: list[str], *, allow_empty: bool = False
) -> None:
    if not isinstance(patterns, list) or (not patterns and not allow_empty):
        requirement = "an array" if allow_empty else "a non-empty array"
        violations.append(f"{field} must be {requirement}")
        return
    for index, pattern in enumerate(patterns):
        if not isinstance(pattern, str) or not _is_safe_relative_path(pattern):
            violations.append(f"{field}[{index}] must be a safe relative path pattern")
    if all(isinstance(pattern, str) for pattern in patterns) and len(patterns) != len(
        set(patterns)
    ):
        violations.append(f"{field} must not contain duplicates")


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
        "operation_constraints",
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
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("id"), str)
            or not value["id"]
        ):
            violations.append(f"{field}.id must be a non-empty string")
        elif isinstance(value, dict):
            _reject_unknown_fields(value, {"id", "display_name"}, field, violations)
            if "display_name" in value and not isinstance(value["display_name"], str):
                violations.append(f"{field}.display_name must be a string")

    capabilities = contract["capabilities"]
    if not isinstance(capabilities, list) or not capabilities:
        violations.append("capabilities must be a non-empty array")
    elif not all(isinstance(capability, str) for capability in capabilities):
        violations.append("capabilities must contain strings")
    else:
        unknown = sorted(set(capabilities) - KNOWN_CAPABILITIES)
        if unknown:
            violations.append(
                f"capabilities contains unknown values: {', '.join(unknown)}"
            )
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
                    repo,
                    {"name", "refs", "allow_paths", "deny_paths"},
                    prefix,
                    violations,
                )
                name = repo.get("name")
                if not isinstance(name, str) or not name:
                    violations.append(f"{prefix}.name must be a non-empty string")
                elif name in names:
                    violations.append(f"{prefix}.name duplicates repository {name!r}")
                else:
                    names.add(name)
                refs = repo.get("refs")
                if (
                    not isinstance(refs, list)
                    or not refs
                    or not all(isinstance(ref, str) and ref for ref in refs)
                ):
                    violations.append(f"{prefix}.refs must be a non-empty string array")
                elif len(refs) != len(set(refs)):
                    violations.append(f"{prefix}.refs must not contain duplicates")
                _validate_patterns(
                    repo.get("allow_paths"), f"{prefix}.allow_paths", violations
                )
                _validate_patterns(
                    repo.get("deny_paths"),
                    f"{prefix}.deny_paths",
                    violations,
                    allow_empty=True,
                )

        channels = scope.get("channels")
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
        not_before = _parse_time(
            validity.get("not_before"), "validity.not_before", violations
        )
        expires_at = _parse_time(
            validity.get("expires_at"), "validity.expires_at", violations
        )
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
        if not _is_finite_nonnegative_number(cost):
            violations.append(
                "limits.max_cost_usd must be a finite non-negative number"
            )

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
            if (
                not isinstance(approvers, list)
                or not approvers
                or not all(
                    isinstance(approver, str) and approver for approver in approvers
                )
            ):
                violations.append(
                    f"{prefix}.approvers must be a non-empty string array"
                )
            else:
                if len(approvers) != len(set(approvers)):
                    violations.append(f"{prefix}.approvers must not contain duplicates")
                if isinstance(minimum, int) and minimum > len(set(approvers)):
                    violations.append(
                        f"{prefix}.min_approvals exceeds unique approvers"
                    )

    constraints = contract["operation_constraints"]
    constrained_actions: set[str] = set()
    seen_nonces: set[str] = set()
    if not isinstance(constraints, list):
        violations.append("operation_constraints must be an array")
    else:
        for index, constraint in enumerate(constraints):
            prefix = f"operation_constraints[{index}]"
            if not isinstance(constraint, dict):
                violations.append(f"{prefix} must be an object")
                continue
            _reject_unknown_fields(
                constraint,
                {"action", "operation_digest", "nonce"},
                prefix,
                violations,
            )
            action = constraint.get("action")
            digest = constraint.get("operation_digest")
            nonce = constraint.get("nonce")
            if not isinstance(action, str) or action not in HIGH_RISK_CAPABILITIES:
                violations.append(f"{prefix}.action must be a high-risk capability")
            elif not isinstance(capabilities, list) or action not in capabilities:
                violations.append(f"{prefix}.action must be granted by capabilities")
            else:
                constrained_actions.add(action)
            if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
                violations.append(
                    f"{prefix}.operation_digest must be lowercase SHA-256 hex"
                )
            if not isinstance(nonce, str) or NONCE_PATTERN.fullmatch(nonce) is None:
                violations.append(f"{prefix}.nonce must be 16-128 safe characters")
            elif nonce in seen_nonces:
                violations.append(f"{prefix}.nonce must be unique")
            else:
                seen_nonces.add(nonce)
        granted_high_risk = (
            set(capabilities).intersection(HIGH_RISK_CAPABILITIES)
            if isinstance(capabilities, list)
            and all(isinstance(capability, str) for capability in capabilities)
            else set()
        )
        for action in sorted(granted_high_risk - constrained_actions):
            violations.append(
                f"operation_constraints must bind granted high-risk capability {action!r}"
            )

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
        if (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation < 1
        ):
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
            if not isinstance(value, list) or not all(
                isinstance(item, str) and item for item in value
            ):
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


def _is_finite_nonnegative_number(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        return False
    if isinstance(value, Decimal):
        return value.is_finite() and value >= 0
    return math.isfinite(value) and value >= 0


def _as_decimal(value: int | float | Decimal) -> Decimal:
    return value if isinstance(value, Decimal) else Decimal(str(value))


def _matches_glob(value: str, pattern: str) -> bool:
    value_parts = tuple(value.replace("\\", "/").split("/"))
    pattern_parts = tuple(pattern.replace("\\", "/").split("/"))
    memo: dict[tuple[int, int], bool] = {}

    def match(value_index: int, pattern_index: int) -> bool:
        key = (value_index, pattern_index)
        if key in memo:
            return memo[key]
        if pattern_index == len(pattern_parts):
            result = value_index == len(value_parts)
        elif pattern_parts[pattern_index] == "**":
            result = match(value_index, pattern_index + 1) or (
                value_index < len(value_parts) and match(value_index + 1, pattern_index)
            )
        else:
            result = (
                value_index < len(value_parts)
                and fnmatchcase(value_parts[value_index], pattern_parts[pattern_index])
                and match(value_index + 1, pattern_index + 1)
            )
        memo[key] = result
        return result

    return match(0, 0)


def _trusted_now(now: datetime | None, violations: list[str]) -> datetime | None:
    if now is None:
        return datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        violations.append("evaluator time must include a timezone")
        return None
    return now.astimezone(timezone.utc)


def authorize(
    contract: dict[str, Any],
    request: dict[str, Any],
    *,
    now: datetime | None = None,
    consumed_nonces: frozenset[str] | set[str] | None = None,
) -> Decision:
    try:
        digest = contract_digest(contract)
    except (TypeError, ValueError):
        return Decision(
            False,
            "",
            ("contract must contain canonical JSON values",),
            (),
        )
    violations = list(validate_contract(contract))
    checks: list[str] = []
    if violations:
        return Decision(False, digest, tuple(violations), tuple(checks))
    if not isinstance(request, dict):
        return Decision(
            False, digest, ("request must be a JSON object",), tuple(checks)
        )
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
        "operation",
        "operation_nonce",
        "at",
    }
    _reject_unknown_fields(request, request_fields, "request", violations)
    required_request_fields = request_fields - {
        "path",
        "at",
        "channel",
        "operation",
        "operation_nonce",
    }
    for field in sorted(required_request_fields - request.keys()):
        violations.append(f"missing required request field: {field}")

    # The evaluator's clock is authoritative. A request's self-declared time is
    # parsed for receipt quality but can never extend or revive authorization.
    effective_now = _trusted_now(now, violations)
    if "at" in request:
        _parse_time(request["at"], "request.at", violations)
    not_before = _parse_time(
        contract["validity"]["not_before"], "validity.not_before", violations
    )
    expires_at = _parse_time(
        contract["validity"]["expires_at"], "validity.expires_at", violations
    )
    if not_before and effective_now is not None and effective_now < not_before:
        violations.append("contract is not active yet")
    if expires_at and effective_now is not None and effective_now >= expires_at:
        violations.append("contract has expired")
    checks.append("validity_window")

    if request.get("subject_id") != contract["subject"]["id"]:
        violations.append("subject_id does not match the active contract")
    checks.append("subject")

    configured_channels = contract["scope"]["channels"]
    requested_channel = request.get("channel")
    if "channel" in request and (
        not isinstance(requested_channel, str) or not requested_channel
    ):
        violations.append("request.channel must be a non-empty string")
    if configured_channels and requested_channel not in configured_channels:
        violations.append(f"channel {requested_channel!r} is outside scope")
    checks.append("channel")

    action = request.get("action")
    if not isinstance(action, str):
        violations.append("request.action must be a known capability string")
    elif action not in contract["capabilities"]:
        violations.append(f"capability {action!r} is not granted")
    if (
        isinstance(action, str)
        and action in PATH_REQUIRED_CAPABILITIES
        and request.get("path") is None
    ):
        violations.append(f"request.path is required for {action}")
    checks.append("capability")

    if isinstance(action, str) and action in HIGH_RISK_CAPABILITIES:
        raw_operation = request.get("operation")
        operation: dict[str, Any] | None = (
            raw_operation if isinstance(raw_operation, dict) else None
        )
        nonce = request.get("operation_nonce")
        operation_is_valid = operation is not None
        if operation is None:
            violations.append(
                f"request.operation is required for high-risk action {action!r}"
            )
        else:
            _reject_unknown_fields(
                operation, {"tool", "arguments"}, "request.operation", violations
            )
            if not isinstance(operation.get("tool"), str) or not operation["tool"]:
                violations.append("request.operation.tool must be a non-empty string")
                operation_is_valid = False
            if not isinstance(operation.get("arguments"), dict):
                violations.append("request.operation.arguments must be an object")
                operation_is_valid = False
        if not isinstance(nonce, str) or NONCE_PATTERN.fullmatch(nonce) is None:
            violations.append("request.operation_nonce must be 16-128 safe characters")
        elif consumed_nonces is None:
            violations.append(
                "high-risk authorization requires an explicit consumed_nonces set"
            )
        elif not isinstance(consumed_nonces, (set, frozenset)) or not all(
            isinstance(item, str) for item in consumed_nonces
        ):
            violations.append("consumed_nonces must be a set of strings")
        elif nonce in consumed_nonces:
            violations.append("request.operation_nonce has already been consumed")

        if operation_is_valid and operation is not None and isinstance(nonce, str):
            try:
                requested_operation_digest = operation_digest(action, operation)
            except (TypeError, ValueError):
                violations.append(
                    "request.operation must contain canonical JSON values"
                )
            else:
                matching_constraint = any(
                    constraint.get("action") == action
                    and constraint.get("operation_digest") == requested_operation_digest
                    and constraint.get("nonce") == nonce
                    for constraint in contract["operation_constraints"]
                    if isinstance(constraint, dict)
                )
                if not matching_constraint:
                    violations.append(
                        "request operation and nonce do not match an approved constraint"
                    )
    elif "operation" in request or "operation_nonce" in request:
        violations.append(
            "operation binding fields are only valid for high-risk actions"
        )
    checks.append("operation_binding")

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
            _matches_glob(requested_ref, pattern) for pattern in repository["refs"]
        ):
            violations.append(f"ref {requested_ref!r} is outside scope")

        if "path" in request:
            requested_path = request["path"]
            if not isinstance(requested_path, str) or not _is_safe_relative_path(
                requested_path
            ):
                violations.append("request.path must be a safe relative path")
            else:
                denied = any(
                    _matches_glob(requested_path.casefold(), pattern.casefold())
                    for pattern in repository.get("deny_paths", [])
                )
                allowed = any(
                    _matches_glob(requested_path, pattern)
                    for pattern in repository["allow_paths"]
                )
                if denied:
                    violations.append(f"path {requested_path!r} matches a deny rule")
                elif not allowed:
                    violations.append(
                        f"path {requested_path!r} is outside allowed paths"
                    )
    checks.append("repository_ref_path")

    limits = contract["limits"]
    request_limits = {
        "files_changed": "max_files_changed",
        "commands_used": "max_commands",
        "cost_usd": "max_cost_usd",
    }
    for request_field, limit_field in request_limits.items():
        value = request.get(request_field, 0)
        if request_field == "cost_usd":
            valid_number = _is_finite_nonnegative_number(value)
        else:
            valid_number = (
                isinstance(value, int) and not isinstance(value, bool) and value >= 0
            )
        if not valid_number:
            violations.append(
                f"request.{request_field} must be a finite non-negative number"
            )
        elif request_field == "cost_usd" and _as_decimal(value) > _as_decimal(
            limits[limit_field]
        ):
            violations.append(
                f"request.{request_field}={value} exceeds {limit_field}={limits[limit_field]}"
            )
        elif request_field != "cost_usd" and value > limits[limit_field]:
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
    try:
        digest = contract_digest(contract)
    except (TypeError, ValueError):
        return Decision(
            False,
            "",
            ("contract must contain canonical JSON values",),
            (),
        )
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

    effective_now = _trusted_now(now, violations)
    not_before = _parse_time(
        contract["validity"]["not_before"], "validity.not_before", violations
    )
    expires_at = _parse_time(
        contract["validity"]["expires_at"], "validity.expires_at", violations
    )
    if not_before and effective_now is not None and effective_now < not_before:
        violations.append("contract is not active yet")
    if expires_at and effective_now is not None and effective_now >= expires_at:
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
            violations.append(
                f"completion report.{report_field} must be a string array"
            )
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
    if created_at is None:
        event_created_at = int(datetime.now(timezone.utc).timestamp())
    elif (
        not isinstance(created_at, int)
        or isinstance(created_at, bool)
        or created_at < 0
    ):
        raise ValueError("created_at must be a non-negative integer")
    else:
        event_created_at = created_at
    return {
        "status": "unsigned_template",
        "instruction": "Compute the NIP-01 id and signature with the issuer's Nostr key before publishing.",
        "event": {
            "kind": 30078,
            "created_at": event_created_at,
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
