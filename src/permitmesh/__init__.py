"""PermitMesh: deterministic capability contracts for workspace agents."""

from .policy import (
    Decision,
    authorize,
    contract_digest,
    validate_contract,
    verify_completion,
)
from .conformance import run_conformance

__all__ = [
    "Decision",
    "authorize",
    "contract_digest",
    "run_conformance",
    "validate_contract",
    "verify_completion",
]
__version__ = "0.1.0"
