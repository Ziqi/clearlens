#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""Dual-Mode Continuous Fuzzing Harness (`tests/fuzz_clearlens.py`).

Supports both:
  1. Native Google Atheris / ClusterFuzzLite coverage-guided libFuzzer execution.
  2. Zero-dependency deterministic & structure-aware mutation fuzzing (`--stdlib`)
     executed on every CI push and pull request.
"""

from __future__ import annotations

import argparse
import pathlib
import random
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from clearlens.csp_audit import audit_html_content  # noqa: E402
from clearlens.dlp_guard import redact_sensitive_text, scan_outbound_message  # noqa: E402
from clearlens.ledger import (  # noqa: E402
    extract_payment_iocs,
    iban_mod97_valid,
    luhn_valid,
    parse_tabular_transactions,
    swift_bic_valid,
)


def fuzz_one_bytes(data: bytes) -> None:
    """Exercise all text, HTML/CSP, checksum, and DLP parsers on arbitrary untrusted bytes."""
    clipped = data[:32_768]
    text = clipped.decode("utf-8", errors="replace")

    iocs = extract_payment_iocs(text, redact=False)
    for iban in iocs["mod97_ibans"]:
        if not iban_mod97_valid(iban):
            raise AssertionError(f"Invalid IBAN bypassed Mod-97 gate: {iban!r}")
    for acct in iocs["luhn_accounts"]:
        if not luhn_valid(acct):
            raise AssertionError(f"Invalid Luhn account bypassed gate: {acct!r}")
    for bic in iocs["swift_bics"]:
        if not swift_bic_valid(bic):
            raise AssertionError(f"Invalid SWIFT/BIC bypassed gate: {bic!r}")

    scan = scan_outbound_message(text[:4096])
    if scan["verdict"] not in {"PASS_CLEAN", "WARN_REVIEW", "BLOCK_OUTBOUND"}:
        raise AssertionError(f"Unexpected DLP verdict: {scan['verdict']!r}")

    red = redact_sensitive_text(text[:4096])
    if red["total_redactions"] < 0:
        raise AssertionError("Negative redaction count")

    csp = audit_html_content(text[:8192])
    if not isinstance(csp["passed"], bool):
        raise AssertionError("CSP auditor must return boolean 'passed'")

    try:
        parse_tabular_transactions(text[:2048])
    except ValueError:
        pass


def _mutate_seed(seed_bytes: bytes, rng: random.Random) -> bytes:
    if not seed_bytes:
        return bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 128)))
    buf = bytearray(seed_bytes)
    op = rng.randrange(4)
    if op == 0:
        for _ in range(rng.randint(1, 12)):
            buf[rng.randrange(len(buf))] ^= rng.randint(1, 255)
    elif op == 1:
        del buf[rng.randrange(len(buf)) :]
    elif op == 2:
        pos = rng.randrange(len(buf) + 1)
        buf[pos:pos] = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 48)))
    else:
        start = rng.randrange(len(buf))
        end = min(len(buf), start + rng.randint(1, 96))
        buf.extend(buf[start:end])
    return bytes(buf)


def run_stdlib_campaign(iterations: int, seed: int) -> int:
    rng = random.Random(seed)
    seeds = [
        b"Remit HKD 165,000.00 to DE89370400440532013000 or 6200000000000005 SWIFT HSBCHKHH INV-2026-8841",
        b'<!DOCTYPE html><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; form-action \'none\';"><script>fetch("http://127.0.0.1:11434")</script>',
        b"Urgent police SWIFT recall OTP: 482910 email ops@example.org +1 415-555-0199!!",
        b"2026-05-14 16:05,HKD,165000.00,external_beneficiary,debited,Vendor,6200000000000005\n",
    ]
    for s in seeds + [b"", b"\x00" * 64, b"\xff" * 64, b"<meta http-equiv='Content-Security-Policy' content=''>"]:
        fuzz_one_bytes(s)

    for i in range(iterations):
        raw = (
            bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 2048)))
            if i % 5 == 0
            else _mutate_seed(seeds[i % len(seeds)], rng)
        )
        fuzz_one_bytes(raw)

    print(f"CLEARLENS_STDLIB_FUZZ_OK iterations={iterations} seed={seed}")
    return 0


def main() -> int:
    if "--stdlib" in sys.argv:
        ap = argparse.ArgumentParser()
        ap.add_argument("--stdlib", action="store_true")
        ap.add_argument("--iterations", type=int, default=2500)
        ap.add_argument("--seed", type=int, default=20261115)
        args = ap.parse_args()
        return run_stdlib_campaign(args.iterations, args.seed)

    import atheris  # type: ignore[import-not-found]

    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_one_bytes)
    atheris.Fuzz()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
