# Changelog

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
