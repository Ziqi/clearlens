# ClearLens (澄镜) `v1.0.0`

**Zero-Backend Financial Fraud, Business Email Compromise (BEC) & Digital Coercion Triage Workbench — with Defensive Outbound DLP, Multi-Currency Exposure De-duplication & Dual-Mode A4 Recall Schedules**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![REUSE 3.3 Compliant](https://img.shields.io/badge/REUSE-3.3%20Compliant-brightgreen)](./REUSE.toml)
[![SLSA Level 3](https://img.shields.io/badge/SLSA-Build%20Level%203-0f766e)](https://github.com/Ziqi/clearlens/attestations)
[![Zero Dependencies](https://img.shields.io/badge/Runtime%20Dependencies-0%20(Stdlib%20%2B%20Vanilla%20JS)-success)](./pyproject.toml)
[![Live Offline-CSP Workbench](https://img.shields.io/badge/Workbench-ziqi.github.io%2Fclearlens-1d4ed8)](https://ziqi.github.io/clearlens/)

> **Languages / 语言切换：** **English** | [**简体中文 (`README.zh-CN.md`)**](./README.zh-CN.md)  
> **Live Zero-Backend Workbench:** <https://ziqi.github.io/clearlens/> (Direct 4-Cabin App: <https://ziqi.github.io/clearlens/app.html>)

---

## Why ClearLens?

During the **Golden 72 Hours** of an active **Business Email Compromise (BEC)** vendor-invoice interception, executive impersonation wire fraud, or coercive social-engineering incident, responders face three acute operational failure modes:

1. **Cloud SaaS PII Leakage:** Uploading raw bank statements, spoofed invoices, or internal account numbers to third-party web converters or cloud AI chat tools leaks confidential financial PII outside legal privilege.
2. **Premature Operational Tip-Offs (`Outbound DLP` Gap):** Sending an unvetted external email or message mentioning `SWIFT recall`, `police`, `freeze order`, or an unmasked OTP/IBAN alerts threat actors to disperse funds across downstream accounts before bank holds land.
3. **Double-Counted Multi-Currency Exposure:** Victims and corporate treasuries frequently sweep liquidity across internal same-entity accounts (e.g., `EUR -> HKD`) prior to an external wire. Counting both internal FX hops and external wires inflates reported loss figures and delays bank compliance and law-enforcement intake.

**ClearLens (`澄镜`)** solves all three problems **100% locally inside browser RAM (`web/app.html`) and Python >= 3.10 standard library (`clearlens`)**, locked down by a strict offline `Content-Security-Policy` (`default-src 'none'`).

---

## Four Deterministic Incident-Response Cabins

| Cabin | Module | Capabilities |
| :--- | :--- | :--- |
| **Cabin 01** | **Severity Triage & Persistence Audit** | 3-tier operational triage (`Active Compromise` / `72h Recall Window` / `Post-Incident Audit`), 6-step containment checklist (purging silent mailbox forwarding rules, rogue OAuth tokens, remote-screen persistence, and SIM call diversion while freezing **outbound** bank rails without closing the account), plus browser-RAM `ISO 13616 IBAN Mod-97`, `ISO/IEC 7812 Luhn`, and `ISO 9362 SWIFT/BIC` extraction. |
| **Cabin 02** | **Defensive Outbound DLP Guardrail** | Blue-team pre-flight scanner evaluating external draft replies against operational tip-off terms, OTP passcodes, unredacted IBANs/cards, contact PII, and confrontational tone spikes (`PASS_CLEAN` / `WARN_REVIEW` / `BLOCK_OUTBOUND`). Includes deterministic HMAC-style PII redaction and opt-in loopback `127.0.0.1:11434` Ollama drafting. |
| **Cabin 03** | **Multi-Currency Ledger & FX Stripping** | Ephemeral `blob:` side-by-side receipt viewer, cross-timezone UTC session-window alignment, `Decimal`-accurate multi-currency normalization, automatic stripping of `internal_transit` same-entity FX sweeps and `held_by_risk_control` suspense items, and pure inline `<svg>` fund-flow visualization. |
| **Cabin 04** | **Dual-Mode A4 Recall Workpaper** | One-click toggle between a **Full Bank SWIFT Recall & Law-Enforcement Schedule** and a **Redacted External Counsel Brief** (masking internal payer accounts while preserving actionable external fraudulent beneficiary accounts), rendered cleanly via native `@media print`. |

---

## Quickstart

### Option A — Instant Browser Execution (Zero Install)
- Open **<https://ziqi.github.io/clearlens/app.html>**, or download `clearlens-offline-v1.0.0.zip` from [GitHub Releases](https://github.com/Ziqi/clearlens/releases), verify its SLSA Level 3 provenance, disconnect Wi-Fi, and double-click `web/app.html`.
- Click **`Load Synthetic BEC Demo`** in the top toolbar to explore the 100% synthetic `Apex Maritime GmbH` (`SYN-BEC-2026-041`) cross-border invoice interception dataset.

### Option B — Python `>= 3.10` CLI Verification & Ledger Toolkit (Zero Dependencies)

```bash
git clone https://github.com/Ziqi/clearlens.git
cd clearlens

# 1. Audit web/*.html for strict default-src 'none' CSP & zero remote subresources
python3 -m clearlens verify ./web

# 2. Run end-to-end deterministic synthetic BEC demonstration
python3 -m clearlens demo

# 3. Reconcile multi-currency ledger JSON with HMAC payer pseudonymization
python3 -m clearlens ledger --demo --base-currency USD --redact

# 4. Pre-flight scan an outbound draft reply in CI or terminal
python3 -m clearlens dlp-scan --text "Invoice INV-2026-8841 is queued in routine settlement review." --strict

# 5. Serve the workbench strictly on 127.0.0.1 loopback with hardened HTTP headers
python3 -m clearlens serve --host 127.0.0.1 --port 8765
```

---

## Cryptographic Provenance Verification (SLSA Level 3)

Every official release (`clearlens-offline-v1.0.0.zip`, `clearlens.pyz`, and `clearlens-1.0.0.spdx.json`) is built on isolated GitHub-hosted runners and attested with **Sigstore (`Fulcio` + `Rekor`)** and **`slsa-framework/slsa-github-generator` (SLSA Build Level 3)**:

```bash
gh attestation verify clearlens-offline-v1.0.0.zip --repo Ziqi/clearlens
gh attestation verify clearlens.pyz --repo Ziqi/clearlens
```

---

## Companion Ecosystem

ClearLens pairs with [**`starshield-forensics`**](https://github.com/Ziqi/starshield-forensics) (OpenSSF Best Practices Silver `#16602`, Scorecard `8.0/10`, Zenodo DOI [`10.5281/zenodo.24145804`](https://doi.org/10.5281/zenodo.24145804)) — use `starshield` to carve uncompacted Chromium/Electron IndexedDB write-ahead logs and inspect PNG `iCCP` / JPEG `APP2` receipt provenance, then reconcile multi-currency exposure and generate print-ready recall schedules in **ClearLens**.

---

## Clean-Room & Legal Disclaimer

All bundled datasets, corporate names (`Apex Maritime GmbH`, `Harborline Bunker Supply Co`), IBANs (`DE89370400440532013000`, `GB82WEST12345698765432`), and Luhn test numbers (`6200000000000005`) are **100% synthetic ISO/RFC test vectors** containing zero real-world incident data or PII. ClearLens is an independent open-source technical triage and accounting aid under the [MIT License](./LICENSE) and does not constitute formal legal advice.
