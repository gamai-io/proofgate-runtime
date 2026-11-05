"""Signed receipts for evidence-first agent actions (stdlib only).

A receipt binds an intent to a result with SHA-256 digests. An optional
HMAC-SHA256 signature makes it tamper-evident for parties that share a key.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from typing import Any

VERSION = "1"
ALG = "HMAC-SHA256"


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def sha256_hex(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def _key_bytes(key: str | bytes | None) -> bytes | None:
    if key is None:
        return None
    return key.encode("utf-8") if isinstance(key, str) else key


def _core(receipt: dict) -> dict:
    return {k: v for k, v in receipt.items() if k not in ("sig", "receipt_hash")}


def make_receipt(intent: Any, result: Any, key: str | bytes | None = None,
                 meta: dict | None = None) -> dict:
    """Create a receipt. If key is provided, add an HMAC-SHA256 signature."""
    receipt = {
        "v": VERSION,
        "receipt_id": str(uuid.uuid4()),
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "intent": intent,
        "result": result,
        "intent_hash": sha256_hex(intent),
        "result_digest": sha256_hex(result),
    }
    if meta:
        receipt["meta"] = meta
    receipt["receipt_hash"] = sha256_hex(_core(receipt))
    kb = _key_bytes(key)
    if kb:
        receipt["sig"] = {
            "alg": ALG,
            "value": hmac.new(kb, receipt["receipt_hash"].encode("utf-8"),
                              hashlib.sha256).hexdigest(),
        }
    return receipt


def verify_receipt(receipt: dict, key: str | bytes | None = None,
                   require_signature: bool = False) -> dict:
    """Verify hashes and, when present, the signature. Fail closed."""
    errors: list[str] = []
    if not isinstance(receipt, dict):
        return {"valid": False, "signed": False, "errors": ["E_NOT_OBJECT"]}
    for field in ("v", "receipt_id", "created", "intent_hash", "result_digest",
                  "receipt_hash"):
        if field not in receipt:
            errors.append("E_MISSING_" + field.upper())
    if "intent" not in receipt:
        errors.append("E_MISSING_INTENT")
    if "result" not in receipt:
        errors.append("E_MISSING_RESULT")
    if "intent" in receipt and receipt.get("intent_hash") != sha256_hex(receipt["intent"]):
        errors.append("E_INTENT_HASH")
    if "result" in receipt and receipt.get("result_digest") != sha256_hex(receipt["result"]):
        errors.append("E_RESULT_DIGEST")
    core = _core(receipt)
    if receipt.get("receipt_hash") != sha256_hex(core):
        errors.append("E_RECEIPT_HASH")
    signed = "sig" in receipt
    if require_signature and not signed:
        errors.append("E_UNSIGNED")
    if signed:
        sig = receipt.get("sig") or {}
        if sig.get("alg") != ALG:
            errors.append("E_SIG_ALG")
        kb = _key_bytes(key)
        if kb is None:
            errors.append("E_NO_KEY")
        else:
            want = hmac.new(kb, str(receipt.get("receipt_hash", "")).encode("utf-8"),
                            hashlib.sha256).hexdigest()
            if not hmac.compare_digest(str(sig.get("value", "")), want):
                errors.append("E_SIGNATURE")
    return {"valid": not errors, "signed": signed, "errors": errors,
            "receipt_hash": receipt.get("receipt_hash")}


def verify_chain(receipts: list[dict], key: str | bytes | None = None) -> dict:
    """Verify a simple prev_hash chain (first prev_hash = GENESIS)."""
    errors: list[str] = []
    prev = "GENESIS"
    for i, rec in enumerate(receipts or []):
        if rec.get("prev_hash") != prev:
            errors.append("E_CHAIN_AT_%d" % i)
        res = verify_receipt(rec, key=key)
        if not res["valid"]:
            errors.extend("%s@%d" % (e, i) for e in res["errors"])
        prev = rec.get("receipt_hash", "")
    return {"valid": not errors, "count": len(receipts or []), "errors": errors}
