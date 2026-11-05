"""ProofGate Runtime — evidence-first claim verification and signed receipts."""
from .claims import evaluate, check, verify, demo, EvidenceError
from .guard import check_injection
from .receipts import make_receipt, verify_receipt, verify_chain, canonical_json, sha256_hex

__version__ = "0.2.0"

__all__ = [
    "evaluate", "check", "verify", "demo", "EvidenceError",
    "check_injection", "make_receipt", "verify_receipt", "verify_chain",
    "canonical_json", "sha256_hex", "__version__",
]
