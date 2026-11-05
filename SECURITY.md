# Security Policy

## Supported versions

`proofgate-runtime` 0.1.x receives security fixes.

## Reporting

Email **security@gamai.io** with:
- affected version,
- a minimal reproducer or receipt/claim JSON,
- impact and whether the issue is already public.

Do not open a public issue for an unpatched vulnerability.

## Scope

In scope:
- hash/canonicalization bypasses,
- receipt tampering or signature bypass,
- fail-open behavior in `verify_claims` / `verify_receipt`,
- injection patterns that bypass the lexical layer in a dangerous way.

Out of scope:
- the lite guard missing sophisticated/obfuscated injections (it is lexical by design),
- unsigned receipts accepted without `--require-signature` (documented),
- the absence of an independent audit (see README).

## Handling secrets

- Never put tokens, passwords or private keys in `intent` or `result`; receipts hash them but the plaintext is still stored.
- Keep HMAC key files outside the repository and set restrictive permissions (`chmod 600`).
- Receipts are not encryption; they are tamper-evidence.

## Status

v0.1.0 is a reference implementation and has **not** been independently audited.

Internal audit (2026-11-05): https://github.com/gamai-io/.github/blob/main/security/2026-11-05-audit.md

External audit RFP (draft): docs/external-audit-rfp.md
