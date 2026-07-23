from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from permitmesh.policy import (
    authorize,
    contract_digest,
    to_nostr_event_template,
    validate_contract,
)


ROOT = Path(__file__).resolve().parents[1]


def load_example(name: str) -> dict:
    return json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))


class ContractValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load_example("contract.valid.json")

    def test_valid_contract(self) -> None:
        self.assertEqual(validate_contract(self.contract), ())

    def test_digest_is_stable_and_ignores_signature(self) -> None:
        original = contract_digest(self.contract)
        signed = deepcopy(self.contract)
        signed["signature"] = {
            "algorithm": "example-only",
            "public_key": "abc",
            "value": "def",
        }
        self.assertEqual(original, contract_digest(signed))

    def test_rejects_traversal_in_contract_pattern(self) -> None:
        self.contract["scope"]["repositories"][0]["allow_paths"] = ["../other/**"]
        self.assertIn(
            "scope.repositories[0].allow_paths[0] must be a safe relative path pattern",
            validate_contract(self.contract),
        )

    def test_rejects_impossible_approval_threshold(self) -> None:
        self.contract["approval_gates"][0]["min_approvals"] = 2
        self.assertIn(
            "approval_gates[0].min_approvals exceeds unique approvers",
            validate_contract(self.contract),
        )

    def test_rejects_unknown_contract_field(self) -> None:
        self.contract["surprise"] = True
        self.assertIn(
            "contract contains unknown field: surprise",
            validate_contract(self.contract),
        )

    def test_rejects_non_finite_cost_limit(self) -> None:
        self.contract["limits"]["max_cost_usd"] = float("nan")
        self.assertIn(
            "limits.max_cost_usd must be a finite non-negative number",
            validate_contract(self.contract),
        )


class AuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load_example("contract.valid.json")
        self.request = load_example("request.allowed.json")
        self.now = datetime(2026, 7, 23, 12, tzinfo=timezone.utc)

    def test_allows_in_scope_action(self) -> None:
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.violations, ())
        self.assertEqual(
            decision.checks,
            (
                "validity_window",
                "capability",
                "repository_ref_path",
                "budgets",
                "claim_and_fence",
                "approval_gates",
            ),
        )

    def test_denial_explains_every_violation(self) -> None:
        denied = load_example("request.denied.json")
        decision = authorize(self.contract, denied, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertGreaterEqual(len(decision.violations), 7)
        self.assertTrue(any("approval" in item for item in decision.violations))
        self.assertTrue(any("deny rule" in item for item in decision.violations))
        self.assertTrue(any("fencing_generation" in item for item in decision.violations))

    def test_expired_contract_fails_closed(self) -> None:
        future = datetime(2026, 8, 1, tzinfo=timezone.utc)
        decision = authorize(self.contract, self.request, now=future)
        self.assertFalse(decision.allowed)
        self.assertIn("contract has expired", decision.violations)

    def test_backdated_request_cannot_revive_expired_contract(self) -> None:
        self.request["at"] = "2026-07-23T00:00:00Z"
        future = datetime(2026, 8, 1, tzinfo=timezone.utc)
        decision = authorize(self.contract, self.request, now=future)
        self.assertFalse(decision.allowed)
        self.assertIn("contract has expired", decision.violations)

    def test_path_traversal_fails_closed(self) -> None:
        self.request["path"] = "../other-repo/secrets.txt"
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn("request.path must be a safe relative path", decision.violations)

    def test_deploy_requires_approval(self) -> None:
        self.request["action"] = "deploy"
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.request["approvals"] = [
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ]
        self.assertTrue(authorize(self.contract, self.request, now=self.now).allowed)

    def test_stale_fence_fails_closed(self) -> None:
        self.request["fencing_generation"] = 2
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn(
            "fencing_generation does not match the active contract",
            decision.violations,
        )

    def test_missing_request_fields_fail_closed(self) -> None:
        decision = authorize(self.contract, {"action": "edit"}, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn("missing required request field: repository", decision.violations)
        self.assertIn("request.path is required for edit", decision.violations)

    def test_malformed_approvals_fail_closed(self) -> None:
        self.request["approvals"] = (
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn("request.approvals must be a string array", decision.violations)

    def test_non_finite_request_cost_fails_closed(self) -> None:
        self.request["cost_usd"] = float("inf")
        decision = authorize(self.contract, self.request, now=self.now)
        self.assertFalse(decision.allowed)
        self.assertIn(
            "request.cost_usd must be a finite non-negative number",
            decision.violations,
        )


class NostrAdapterTests(unittest.TestCase):
    def test_event_is_explicitly_unsigned(self) -> None:
        contract = load_example("contract.valid.json")
        envelope = to_nostr_event_template(contract, created_at=1784800000)
        event = envelope["event"]
        self.assertEqual(event["kind"], 30078)
        self.assertEqual(event["created_at"], 1784800000)
        self.assertEqual(event["sig"], "")
        self.assertEqual(envelope["status"], "unsigned_template")
        digest = contract_digest(contract)
        self.assertIn(["x", digest], event["tags"])

    def test_event_adapter_rejects_non_nostr_principal(self) -> None:
        contract = load_example("contract.valid.json")
        contract["subject"]["id"] = "agent@example.com"
        with self.assertRaisesRegex(ValueError, "subject.id must be"):
            to_nostr_event_template(contract, created_at=1784800000)


if __name__ == "__main__":
    unittest.main()
