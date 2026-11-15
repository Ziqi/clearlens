# Contributing to `ClearLens`

Thank you for contributing to `ClearLens` (`澄镜`). Because this workbench is deployed in high-stakes BEC wire-fraud containment and crisis triage, all contributions must preserve **zero-backend network isolation, stdlib-only Python portability, and 100% synthetic clean-room test fixtures**.

## 1. Quick Development Setup (< 30 Seconds)

`ClearLens` requires **Python >= 3.10** and **zero external runtime dependencies**:

```bash
git clone https://github.com/Ziqi/clearlens.git
cd clearlens

# Audit web/*.html for strict offline CSP & zero remote subresources
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -m clearlens verify ./web

# Run unit & clean-room OPSEC tests under strict warnings
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -W error -m unittest discover -s tests -v

# Run 2,500 structure-aware fuzzing iterations
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -W error tests/fuzz_clearlens.py --stdlib --iterations 2500

# Build and verify bit-for-bit reproducible offline ZIP & PYZ bundles
python3 scripts/build_reproducible_bundle.py --verify
```

## 2. Developer Certificate of Origin (DCO 1.1) & Licensing

All contributions are licensed under the **MIT License** (`LICENSE`). Every commit MUST include a `Signed-off-by:` trailer (`git commit -s`) certifying compliance with the [Developer Certificate of Origin v1.1](https://developercertificate.org/):

```text
Signed-off-by: Random J Developer <random@developer.example.org>
```

**Clean-Room Fixture Rule:** Never submit real client data, live case artifacts, or personal identifiable information (PII). All examples and test vectors MUST use synthetic ISO test identifiers (such as `DE89370400440532013000`, `GB82WEST12345698765432`, and Luhn test card `6200000000000005`).

## 3. Coding Standards & Automated CI Gates

- `ruff check clearlens tests scripts` (0 lint errors)
- `bandit -q -r clearlens scripts` (0 security warnings)
- `fsfe/reuse-action` (100% SPDX header/REUSE 3.3 compliance)
- `coverage report --include="clearlens/*" --fail-under=90` (`>= 90%` statement coverage enforced on every PR)
- Zero external `<script>`, `<link>`, `<img>`, or font CDN URLs inside `web/`

## 4. Mandatory Automated Testing & Regression Policy

1. **New Functionality Policy (`test_policy_mandated`):** Every pull request adding or modifying logic MUST include positive and malformed-input unit tests in `tests/`.
2. **Bug-Fix Regression Policy (`regression_tests_added50`):** Every bug fix MUST include a deterministic regression test reproducing the defect prior to the fix.
