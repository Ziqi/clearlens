# Security Policy & Vulnerability Response Process

## 1. Supported Versions & Upgrade Path

`clearlens` follows Semantic Versioning (`MAJOR.MINOR.PATCH`). Security updates are published to the latest `1.0.x` release line with a zero-dependency drop-in upgrade path (replacing the static `clearlens-offline-v1.0.x.zip` bundle or `clearlens.pyz` after verifying SLSA Level 3 build provenance via `gh attestation verify`).

| Version | Supported |
| :--- | :--- |
| `1.0.x` (latest) | Supported |
| `< 1.0.0` | Upgrade directly to `1.0.0` |

## 2. Private Vulnerability Reporting (`vulnerability_report_private`)

Please **do not** report security vulnerabilities (such as Content-Security-Policy bypasses, DOM XSS vectors in A4 schedule rendering, Outbound DLP filter evasion, or parser memory exhaustion) via public GitHub issues.

Submit reports privately over HTTPS via **GitHub Private Vulnerability Reporting**:
- **URL:** <https://github.com/Ziqi/clearlens/security/advisories/new>

Provide a minimal synthetic proof-of-concept input (never attach real incident data or PII) and expected versus observed behavior.

## 3. Documented Vulnerability Response Process (`vulnerability_response_process`)

1. **Acknowledgment:** Within **48 hours** of private submission.
2. **Triage & Reproduction:** Within **5 calendar days**, confirming severity, affected components (`web/` or `clearlens/`), and CWE classification.
3. **Remediation & Regression Test:** Within **14 calendar days** for High/Critical issues (or **30 days** for Low/Medium), accompanied by an automated regression test in `tests/`.
4. **Coordinated Disclosure & Attested Release:** Publication of a SLSA Level 3 attested release (`multiple.intoto.jsonl` + SPDX 2.3 SBOM) and GitHub Security Advisory (GHSA/CVE where applicable).

## 4. Reporter Credit Policy (`vulnerability_report_credit`)

All reporters of resolved security vulnerabilities are credited in the corresponding GitHub Security Advisory and Release Notes unless anonymity is requested. (Zero vulnerabilities reported in the past 12 months.)

## 5. OpenSSF OSPS Baseline (Level 3) & EU Cyber Resilience Act (CRA) Alignment

`clearlens` implements machine-verifiable security controls aligned with the **OpenSSF Open Source Project Security (OSPS) Baseline (Level 3)** and **EU Cyber Resilience Act (Regulation (EU) 2024/2847, Annex I)**:

| Control Domain | OSPS Baseline / EU CRA Reference | Repository Implementation & Verifiable Evidence |
| :--- | :--- | :--- |
| **Access Control & Governance** | `OSPS-AC` / `OSPS-GV` | Documented roles & continuity policy (`GOVERNANCE.md`), mandatory DCO 1.1 sign-off (`CONTRIBUTING.md`), and SHA-pinned GitHub Actions with `permissions: contents: read` & `persist-credentials: false`. |
| **Build & Release Integrity** | `OSPS-BR` / SLSA v1.0 L3 | Isolated **SLSA Build Level 3** provenance (`multiple.intoto.jsonl`), GitHub OIDC + Sigstore (`Fulcio`/`Rekor`) `/attestations`, and bit-for-bit reproducible `clearlens-offline-v1.0.0.zip` & `clearlens.pyz` (`scripts/build_reproducible_bundle.py --verify`). |
| **SBOM & Licensing** | `OSPS-DO` / `OSPS-LE` / CRA Annex I Part I §2(2) | Deterministic ISO/IEC 5962:2021 **SPDX 2.3 SBOM** (`scripts/generate_spdx_sbom.py --verify`), 100% **FSFE REUSE 3.3** SPDX compliance (`REUSE.toml`), and OpenSSF `SECURITY-INSIGHTS.yml` (`v2.0.0`). |
| **Quality, SAST & Continuous Fuzzing** | `OSPS-QA` / CRA Annex I Part I §2(1) | Zero third-party runtime dependencies (`dependencies = []` + vanilla browser JS), automated `CodeQL` (Python + JS) & `Bandit` SAST, `>= 90%` statement coverage gate, and **ClusterFuzzLite / Atheris** continuous fuzzing (`cflite.yml`). |
| **Vulnerability Handling & CVD** | `OSPS-VM` / CRA Annex I Part II | Private HTTPS reporting via GitHub Security Advisories (§2), 48-hour acknowledgment SLA, and 14-day High/Critical remediation target (§3). |
| **Privacy & Network Isolation by Default** | `OSPS-SA` / CRA Annex I Part I §1 | Browser execution locked down via `Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'`, audited on every commit by `clearlens verify`. |
