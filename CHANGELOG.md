# Changelog

## 0.2.0 — 2026-11-05

- **Breaking:** `verify_receipt()` requires a valid HMAC signature by default; use `require_signature=False`/`--allow-unsigned` only for legacy unsigned receipts.
- MCP `make_receipt` signs with `PROOFGATE_HMAC_KEY`; unsigned MCP receipts get `_warning` and fail verification by default.
- CLI `make-receipt` refuses unsigned receipts unless `--allow-unsigned`; `verify-receipt` exits non-zero on invalid.
- README/limitations updated.

## 0.1.0 — 2026-11-05

- Claim verification (`verify_claims`): confirmed/refuted/unverified, fail-closed,
  SHA-256-bound report; BHS/EU/US money formats.
- Signed receipts (`make_receipt`, `verify_receipt`): SHA-256 intent/result digests,
  optional HMAC-SHA256 signature.
- Lite lexical prompt-injection guard (`check_injection`).
- MCP stdio server (`proofgate-runtime` tools) and CLI (`proofgate`).
- Tests + CI (Python 3.10–3.12).
- Published to PyPI as `proofgate-runtime` 0.1.0.
- Extracted from `gamai-io/gamai-trust` proofgate (Apache-2.0).
