"""PermitMesh: deterministic capability contracts for workspace agents."""

from .policy import (
    Decision,
    IMPLEMENTATION_VERSION,
    authorize,
    contract_digest,
    operation_digest,
    validate_contract,
    verify_completion,
)
from .conformance import run_conformance

__all__ = [
    "Decision",
    "authorize",
    "contract_digest",
    "operation_digest",
    "run_conformance",
    "validate_contract",
    "verify_completion",
]
__version__ = IMPLEMENTATION_VERSION
