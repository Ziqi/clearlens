# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""Command-Line Interface for ClearLens (`clearlens`).

Subcommands:
  - `clearlens verify [PATH]`   : Audit static HTML workbench for strict offline CSP & zero external assets
  - `clearlens ledger ...`      : De-duplicate multi-currency transactions & strip internal FX transit
  - `clearlens dlp-scan ...`    : Scan outbound crisis replies for operational tip-offs & unredacted PII
  - `clearlens demo`            : Run end-to-end synthetic BEC triage verification (`Apex Maritime GmbH`)
  - `clearlens serve`           : Serve the offline workbench strictly on `127.0.0.1` loopback with CSP headers
"""

from __future__ import annotations

import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import io
import ipaddress
import json
from pathlib import Path
import secrets
import socket
import sys
from typing import Any
import urllib.parse

from clearlens import __version__
from clearlens.csp_audit import audit_html_file, audit_web_directory
from clearlens.dlp_guard import (
    build_redacted_local_llm_prompt,
    evaluate_crisis_hygiene_checklist,
    redact_sensitive_text,
    scan_outbound_message,
)
from clearlens.ledger import (
    build_synthetic_bec_incident,
    compute_ledger_exposure,
    extract_payment_iocs,
)


def _default_web_dir() -> Path:
    repo_candidate = Path(__file__).resolve().parent.parent / "web"
    if repo_candidate.is_dir():
        return repo_candidate
    return Path.cwd() / "web"


class _HardenedLoopbackHandler(SimpleHTTPRequestHandler):
    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def list_directory(self, path: str | Any) -> io.BytesIO | None:
        self.send_error(403, "Directory listing disabled in hardened ClearLens server")
        return None

    def send_head(self) -> Any:
        root_dir = Path(self.directory).resolve()
        raw_url_path = urllib.parse.unquote(self.path.split("?", 1)[0].split("#", 1)[0])
        rel_parts = [p for p in raw_url_path.split("/") if p and p != "."]
        if any(p == ".." for p in rel_parts):
            self.send_error(403, "Forbidden path traversal")
            return None
        cur = root_dir
        for part in rel_parts:
            cur = cur / part
            if cur.is_symlink():
                self.send_error(403, "Forbidden symlink target")
                return None
        if cur.is_dir():
            idx = cur / "index.html"
            if idx.is_symlink() or not idx.is_file():
                self.send_error(403, "Directory listing disabled")
                return None
            cur = idx
        try:
            resolved = cur.resolve()
        except OSError:
            self.send_error(404, "File not found")
            return None
        if not resolved.is_relative_to(root_dir):
            self.send_error(403, "Forbidden path outside web bundle root")
            return None
        return super().send_head()

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("[clearlens-local] " + (fmt % args) + "\n")


class _IPv6LoopbackHTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def _cmd_verify(args: argparse.Namespace) -> int:
    target = Path(args.path) if args.path else _default_web_dir()
    if target.is_file():
        report = audit_html_file(target)
        passed = report["passed"]
    else:
        report = audit_web_directory(target)
        passed = report["all_passed"]
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if passed else 1


def _cmd_ledger(args: argparse.Namespace) -> int:
    if args.demo or not args.input:
        dataset = build_synthetic_bec_incident()
    else:
        raw_text = Path(args.input).read_text(encoding="utf-8")
        dataset = json.loads(raw_text)

    tx_list = dataset["transactions"] if isinstance(dataset, dict) else dataset
    windows = (
        (dataset.get("coercion_windows") or dataset.get("windows") or [])
        if isinstance(dataset, dict)
        else []
    )
    rates = json.loads(args.rates) if args.rates else None
    ephemeral_key = secrets.token_bytes(32) if args.redact else None
    effective_base = (
        args.base_currency
        if args.base_currency
        else (dataset.get("baseCurrency", "USD") if isinstance(dataset, dict) else "USD")
    )

    result = compute_ledger_exposure(
        tx_list,
        coercion_windows=windows,
        fx_to_usd=rates,
        base_currency=effective_base,
        redact_payer_accounts=args.redact,
        hmac_key=ephemeral_key,
    )
    if isinstance(dataset, dict):
        case_ref = dataset.get("case_ref") or (dataset.get("meta") or {}).get("caseRef")
        if case_ref:
            result["case_ref"] = case_ref
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def _cmd_dlp_scan(args: argparse.Namespace) -> int:
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
    elif args.text is not None:
        text = args.text
    else:
        text = "Payment batch #4412 is queued for dual-signatory cut-off review; status update to follow."

    extra_terms = [t.strip() for t in (args.extra_terms or "").split(",") if t.strip()]
    scan = scan_outbound_message(
        text,
        custom_block_terms=extra_terms,
        max_recommended_chars=args.max_chars,
    )
    output: dict[str, Any] = {"dlp_scan": scan}
    if args.redact:
        session_key = secrets.token_bytes(32)
        output["redacted_preview"] = redact_sensitive_text(
            text,
            session_key=session_key,
            extra_secret_terms=extra_terms,
        )
    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0 if scan["verdict"] != "BLOCK_OUTBOUND" or not args.strict else 2


def _cmd_demo(_args: argparse.Namespace) -> int:
    incident = build_synthetic_bec_incident()
    session_key = b"clearlens-deterministic-demo-seed-v1"
    exposure = compute_ledger_exposure(
        incident["transactions"],
        coercion_windows=incident["coercion_windows"],
        base_currency="USD",
        redact_payer_accounts=True,
        hmac_key=session_key,
    )
    unsafe_draft = "We already filed a police fraud report and SWIFT recall on GB82WEST12345698765432!"
    safe_draft = "Invoice INV-2026-8841 is in scheduled treasury batch review per standard cut-off."
    sample_headers = (
        "Amended wire instructions: remit HKD 165,000.00 to IBAN DE89370400440532013000 "
        "or account 6200000000000005 via SWIFT NWBKGB2L referencing INV-2026-8841."
    )
    checklist = evaluate_crisis_hygiene_checklist({
        "inbox_forwarding_audited": True,
        "oauth_sessions_revoked": True,
        "screen_share_terminated": True,
        "call_diversion_cleared": True,
        "outbound_rails_frozen_only": True,
        "out_of_band_callback_verified": True,
    })
    payload: dict[str, Any] = {
        "tool": "clearlens",
        "version": __version__,
        "synthetic_case_ref": incident["case_ref"],
        "engine_1_ioc_extractor": extract_payment_iocs(sample_headers, redact=True, hmac_key=session_key),
        "engine_2_outbound_dlp": {
            "unsafe_draft_verdict": scan_outbound_message(unsafe_draft)["verdict"],
            "safe_draft_verdict": scan_outbound_message(safe_draft)["verdict"],
            "redacted_llm_prompt": build_redacted_local_llm_prompt(
                sample_headers,
                session_key=session_key,
            ),
        },
        "engine_3_ledger_exposure": exposure["summary"],
        "engine_4_containment_hygiene": checklist,
    }
    web_dir = _default_web_dir()
    if web_dir.is_dir():
        payload["web_bundle_csp_audit"] = {
            "all_passed": audit_web_directory(web_dir)["all_passed"],
            "html_files_checked": audit_web_directory(web_dir)["html_files_checked"],
        }
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        sys.stderr.write(
            f"Refusing non-loopback bind host {args.host!r}: ClearLens is strictly local-only.\n"
        )
        return 2
    target_dir = Path(args.dir) if args.dir else _default_web_dir()
    audit = audit_web_directory(target_dir)
    if not audit["all_passed"]:
        sys.stderr.write("Refusing to serve bundle failing offline CSP audit.\n")
        return 1

    handler_cls = partial(_HardenedLoopbackHandler, directory=str(target_dir.resolve()))
    server_cls = _IPv6LoopbackHTTPServer if args.host == "::1" else ThreadingHTTPServer
    host_fmt = f"[{args.host}]" if ":" in args.host else args.host
    with server_cls((args.host, args.port), handler_cls) as httpd:
        bound_ip = str(httpd.server_address[0])
        if not ipaddress.ip_address(bound_ip.split("%", 1)[0]).is_loopback:
            sys.stderr.write(f"Bound socket {bound_ip!r} is not a loopback address; aborting.\n")
            return 2
        actual_port = httpd.server_address[1]
        sys.stdout.write(f"ClearLens offline workbench listening on http://{host_fmt}:{actual_port}/\n")
        sys.stdout.flush()
        if args.once:
            httpd.handle_request()
            return 0
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            return 0
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clearlens",
        description="ClearLens — Zero-Backend Financial Fraud, BEC & Digital Coercion Triage Toolkit",
    )
    parser.add_argument("--version", action="version", version=f"clearlens {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_verify = sub.add_parser("verify", help="Audit HTML workbench for strict offline CSP & zero remote assets")
    p_verify.add_argument("path", nargs="?", default=None, help="HTML file or web bundle directory")
    p_verify.set_defaults(func=_cmd_verify)

    p_ledger = sub.add_parser("ledger", help="Compute de-duplicated multi-currency exposure & strip internal FX")
    p_ledger.add_argument("--input", type=str, default=None, help="JSON ledger input path")
    p_ledger.add_argument("--demo", action="store_true", help="Run on synthetic Apex Maritime BEC dataset")
    p_ledger.add_argument("--base-currency", type=str, default=None, help="Target ISO 4217 currency (default: USD)")
    p_ledger.add_argument("--rates", type=str, default=None, help="Custom FX rate map to USD as JSON string")
    p_ledger.add_argument("--redact", action="store_true", help="HMAC-pseudonymize internal payer accounts")
    p_ledger.set_defaults(func=_cmd_ledger)

    p_dlp = sub.add_parser("dlp-scan", help="Pre-flight scan draft message against Outbound DLP guardrails")
    p_dlp.add_argument("--text", type=str, default=None, help="Draft message string to scan")
    p_dlp.add_argument("--file", type=str, default=None, help="Path to draft message text file")
    p_dlp.add_argument("--extra-terms", type=str, default="", help="Comma-separated protected keywords")
    p_dlp.add_argument("--max-chars", type=int, default=120, help="Recommended maximum character length")
    p_dlp.add_argument("--redact", action="store_true", help="Include HMAC-redacted preview")
    p_dlp.add_argument("--strict", action="store_true", help="Exit with code 2 when verdict is BLOCK_OUTBOUND")
    p_dlp.set_defaults(func=_cmd_dlp_scan)

    p_demo = sub.add_parser("demo", help="Run deterministic synthetic demonstration across all 4 engines")
    p_demo.set_defaults(func=_cmd_demo)

    p_serve = sub.add_parser("serve", help="Serve offline workbench strictly on 127.0.0.1 loopback")
    p_serve.add_argument("--host", type=str, default="127.0.0.1", help="Loopback bind address (127.0.0.1 only)")
    p_serve.add_argument("--port", type=int, default=8765, help="TCP port (0 for ephemeral)")
    p_serve.add_argument("--dir", type=str, default=None, help="Directory containing web/index.html & app.html")
    p_serve.add_argument("--once", action="store_true", help="Handle a single HTTP request and exit (CI smoke)")
    p_serve.set_defaults(func=_cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
