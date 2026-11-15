# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""ClearLens — Zero-Backend Financial Fraud, BEC & Digital Coercion Triage Toolkit."""

from __future__ import annotations

from clearlens.csp_audit import audit_html_content, audit_html_file, audit_web_directory
from clearlens.dlp_guard import (
    analyze_communication_fingerprint,
    build_redacted_local_llm_prompt,
    evaluate_crisis_hygiene_checklist,
    redact_sensitive_text,
    scan_outbound_message,
)
from clearlens.ledger import (
    VALID_CATEGORIES,
    VALID_STATUSES,
    build_synthetic_bec_incident,
    check_window_alignment,
    compute_ledger_exposure,
    export_ledger_csv,
    extract_payment_iocs,
    iban_mod97_valid,
    luhn_valid,
    parse_tabular_transactions,
    sanitize_csv_cell,
    swift_bic_valid,
)

__version__ = "1.0.0"
__author__ = "Ziqi Xiao"
__license__ = "MIT"

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "VALID_CATEGORIES",
    "VALID_STATUSES",
    "audit_html_content",
    "audit_html_file",
    "audit_web_directory",
    "analyze_communication_fingerprint",
    "build_redacted_local_llm_prompt",
    "build_synthetic_bec_incident",
    "check_window_alignment",
    "compute_ledger_exposure",
    "evaluate_crisis_hygiene_checklist",
    "export_ledger_csv",
    "extract_payment_iocs",
    "iban_mod97_valid",
    "luhn_valid",
    "parse_tabular_transactions",
    "redact_sensitive_text",
    "sanitize_csv_cell",
    "scan_outbound_message",
    "swift_bic_valid",
]
