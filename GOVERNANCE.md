# Project Governance & Continuity Policy

## 1. Governance Model

`ClearLens` (`澄镜`) uses an open, meritocratic **Lead Maintainer** governance model:

- **Decision Making:** Architectural changes, Outbound DLP rule updates, multi-currency reconciliation logic, and release cuts are reviewed publicly via GitHub Pull Requests and Issues at <https://github.com/Ziqi/clearlens>.
- **Technical Priorities:** Where trade-offs arise between feature convenience and client-side privacy isolation, **strict `default-src 'none'` CSP, zero external dependencies, and deterministic arithmetic** take precedence.

## 2. Roles & Responsibilities

| Role | Current Holder(s) | Responsibilities & Permissions |
| :--- | :--- | :--- |
| **Lead Maintainer & Security Architect** | Ziqi Xiao (`@Ziqi`) | Technical roadmap, SLSA Level 3 release engineering, archival, and private security advisory response. |
| **Contributors** | Open Community | Bug reports, synthetic BEC/coercion test vectors, localization packs, and code reviews under MIT + DCO 1.1. |

## 3. Access Continuity & Bus-Factor Resilience (`access_continuity`)

To ensure uninterrupted continuity (issue triage, patch merges, and attested releases within 7 days) even if any single maintainer becomes unavailable:

1. **Unrestricted OSI MIT Licensing & Zero Cloud Lock-In:** Every HTML workbench, Python module, and reproducible build script is MIT-licensed with zero proprietary build infrastructure.
2. **Public Archival:** Releases are archived on GitHub Releases with SLSA Level 3 provenance and submitted to UNESCO / Inria **Software Heritage (`SWHID`)**.
3. **GitHub Successor & Encrypted Escrow:** Repository administration recovery instructions and GitHub Account Successor settings are maintained in an encrypted offline escrow with documented transfer procedures to a designated technical custodian.
