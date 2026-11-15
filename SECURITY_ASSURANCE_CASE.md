# Security Assurance Case, Architecture & 12-Month Roadmap

> **Structured Software Assurance Case (aligned with NIST IR 7608)** for `ClearLens` (`v1.0.0`).

---

## 1. High-Level Architecture (`documentation_architecture`)

`ClearLens` (`澄镜`) is a **zero-backend client-side incident-triage workbench (`web/`) paired with a pure Python >= 3.10 standard-library verification & CLI package (`clearlens/`)**, engineered with zero external runtime dependencies and zero cloud telemetry:

```text
  Local Incident Inputs (Wire Receipts, Amended Invoices, CSV Ledgers, Reply Drafts)
                                       │
         ┌─────────────────────────────┴─────────────────────────────┐
         ▼                                                           ▼
  ┌──────────────────────────────────────┐   ┌──────────────────────────────────────┐
  │ Browser RAM Workbench (`web/*.html`) │   │ Python >= 3.10 CLI (`clearlens/`)    │
  │  • Strict CSP: default-src 'none'    │   │  • Zero third-party PyPI packages    │
  │  • Ephemeral blob: receipt preview   │   │  • `verify`: HTML CSP & tracker gate │
  │  • HTML-escaped DOM & SVG rendering  │   │  • `ledger`: Decimal FX de-dup       │
  │  • Opt-in loopback 127.0.0.1:11434   │   │  • `dlp-scan`: HMAC PII redaction    │
  └──────────────────┬───────────────────┘   └──────────────────┬───────────────────┘
                     └─────────────────────┬────────────────────┘
                                           ▼
        Print-Ready A4 Bank Recall / Evidentiary Schedule & Deterministic JSON
```

---

## 2. Security Expectations & Operational Boundaries (`documentation_security`)

### What Users CAN Expect
- **Enforced Browser Network Isolation:** `web/index.html` and `web/app.html` embed strict `<meta http-equiv="Content-Security-Policy">` policies (`default-src 'none'; base-uri 'none'; form-action 'none'`), verified in CI by `clearlens verify`. Only loopback `http://127.0.0.1:11434` is permitted on `web/app.html` for optional local Ollama usage.
- **Ephemeral In-Memory Receipt Handling:** Local receipt screenshots are rendered via `URL.createObjectURL` in browser RAM, never persisted to `localStorage`/`IndexedDB` or transmitted over the network, and revoked on `Purge Session RAM` or `beforeunload`.
- **Deterministic Financial Precision:** Ledger de-duplication in `clearlens/ledger.py` uses `decimal.Decimal` (`ROUND_HALF_UP`) rather than binary floating-point arithmetic, preventing rounding drift when stripping internal FX sweeps.
- **CSV Formula-Injection Neutralization:** Exported CSV schedules prefix leading `=`, `+`, `-`, or `@` characters with a single quote (`'`) to prevent spreadsheet formula execution (`CWE-1236`).

### What Users CANNOT Expect (Explicit Non-Guarantees)
- **Not Endpoint Malware Remediation:** If an operator runs ClearLens on a host actively compromised by a kernel keylogger or screen-capture trojan, browser isolation cannot hide on-screen content; Cabin 01 explicitly instructs switching to a clean device for credential resets.
- **Not Formal Legal Advice:** Generated A4 schedules organize factual accounting and routing identifiers to accelerate bank SWIFT recall and law-enforcement intake; they do not substitute for licensed legal counsel.

---

## 3. Threat Model & Trust Boundaries (`assurance_case`)

1. **T1 — Malicious HTML/XSS Injection via Spoofed Email Headers or Counterparty Names (`CWE-79`):** Threat actors may embed `<script>` or `<img onerror=...>` payloads inside email headers, invoice notes, or CSV rows pasted into ClearLens.
   - *Mitigation:* Strict `escHtml()` entity encoding across all dynamic DOM/SVG/A4 interpolations + CSP `default-src 'none'`.
2. **T2 — Accidental Cloud Exfiltration or Third-Party Tracker Leakage (`CWE-359`):** Static web portals frequently leak user IP/metadata via CDN scripts or remote web fonts.
   - *Mitigation:* Zero external subresources; automated `clearlens.csp_audit` AST gate on every commit.
3. **T3 — Operational Tip-Off During Active Bank Recall (`Outbound DLP`):** Prematurely mentioning `SWIFT recall`, `police`, or `freeze` to an impersonator accelerates mule cash-out.
   - *Mitigation:* Cabin 02 & `clearlens dlp-scan` enforce `BLOCK_OUTBOUND` on operational tip-off terms, OTPs, and unredacted IBAN/Luhn identifiers.
4. **T4 — Supply-Chain Compromise:**
   - *Mitigation:* Zero runtime dependencies, SHA-256 hash-pinned CI tools, SHA-pinned GitHub Actions, bit-for-bit reproducible bundles, and SLSA Build Level 3 provenance.

---

## 4. Countermeasures Against Common Implementation Weaknesses (CWE)

| Weakness Class | CWE ID | Countermeasure & Verification Evidence |
| :--- | :--- | :--- |
| Cross-Site Scripting (DOM XSS) | CWE-79 | Strict `escHtml()` sanitization on all template interpolations + `CodeQL` JavaScript & Python SAST (`codeql.yml`). |
| CSV Formula Injection | CWE-1236 | `escCsv()` neutralizes leading `=`, `+`, `-`, `@` tokens before CSV export. |
| Uncontrolled Memory Consumption | CWE-400 | Explicit byte ceilings (`2 MB` IOC scan, `1 MB` DLP redaction, `10 MB` HTML audit) + continuous fuzzing (`tests/fuzz_clearlens.py`). |
| Arbitrary Code Execution | CWE-94 / CWE-502 | Zero use of `eval`, `Function`, `pickle`, `yaml.load`, or `shell=True`; verified by `Bandit` (`0` findings). |
| Non-Loopback Server Exposure | CWE-668 | `clearlens serve` refuses non-loopback `--host` binds (`0.0.0.0` rejected with exit code `2`). |

---

## 5. 12-Month Technical Roadmap

- **Q1–Q2 2027:** Expand ISO 20022 `pacs.008` / `camt.056` XML recall message field mapping in Cabin 04 (pure client-side parser).
- **Q3 2027:** Add offline `.eml` RFC 5322 `Received:` hop & `Authentication-Results` (`SPF/DKIM/DMARC`) discrepancy highlighter in Cabin 01.
- **Q4 2027:** Extend multilingual UI packs (`de`, `fr`, `ja`) while preserving single-file air-gapped portability.
