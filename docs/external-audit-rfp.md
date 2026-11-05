# External security audit — Request for Proposal (draft)

**Status:** vendor RFP draft. No customer data is included.
**Owner:** gamAI / GAMA TRADE d.o.o., Usora, Bosnia and Herzegovina
**Contact:** security@gamai.io
**Date:** 2026-11-05

## 1. Purpose
Independent review of the evidence/trust layer before production claims and before public-sector or enterprise use.

## 2. Scope
- `sigil` 0.22.x — gate, authorize, receipts, anchor, MCP/A2A middleware, conformance suite.
- `proofgate-runtime` 0.2.x — claim verification, signed receipts, lite guard, MCP/CLI.
- `gnp-trust` — node token gate, action tiers, leases/fencing, audit.
- `floor-copilot` — invoice API, upload limits, optional API key, evidence store, arithmetic gate.
- Deployment references: SIGIL Docker compose (gate/verify/anchor/kms/context/edge), GNP node/hub.

Out of scope: LUMI/EuroHPC cluster internals, third-party SaaS, customer data, social engineering.

## 3. Required work
1. Threat model and attack-surface review (STRIDE or equivalent).
2. Manual code review of auth, token handling, receipt/HMAC verification, path handling, subprocess use, upload handling, secret storage.
3. Dependency and container review (SBOM, known CVEs, image hardening).
4. Dynamic checks: auth bypass, receipt tampering, replay/idempotency, oversized upload, path traversal, cache poisoning.
5. Findings with severity (CVSS or equivalent), exact file/line, reproducible steps, impact, remediation.
6. Retest of fixes and a signed attestation letter.

## 4. Deliverables
- Executive summary (1 page).
- Detailed findings register (CSV/JSON + PDF).
- Reproducers and evidence (no secrets).
- Remediation plan and retest report.
- Attestation letter suitable for grant/customer due diligence.

## 5. Rules of engagement
- Written authorization and NDA before access.
- No customer data; use synthetic or anonymized inputs.
- No destructive tests on production; staging only.
- Findings shared privately first; coordinated disclosure.
- Fixed-price proposal preferred; estimate 2–4 weeks plus retest.

## 6. Proposal format
- Firm profile and 2 relevant references.
- Methodology and tools.
- Team, timeline, price (fixed or capped).
- Assumptions and exclusions.
- Conflict-of-interest statement.

## 7. Evaluation
- Relevant agent/LLM security experience (40%).
- Methodology and reproducibility (25%).
- Timeline (15%).
- Price (20%).

## 8. Note
The internal audit at `.github/security/2026-11-05-audit.md` is **not** a substitute for this engagement. It is an internal static review with accepted risks and does not carry an independent attestation.
