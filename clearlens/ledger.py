# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""Deterministic Multi-Currency Ledger De-duplication, IOC Checksums & UTC Window Alignment.

Separates genuine external fraudulent wires (`external_beneficiary`) and diverted vendor/merchant
settlements (`asset_diversion`) from internal same-entity treasury/FX transfers (`internal_transit`),
risk-control held transfers (`held_by_risk_control`), and duplicate ledger entries, preventing
double-counted exposure figures in bank SWIFT gpi recall requests and evidentiary schedules.
"""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import hashlib
import hmac
import io
import math
import re
from typing import Any

VALID_CATEGORIES: tuple[str, ...] = (
    "external_beneficiary",
    "asset_diversion",
    "internal_transit",
)

VALID_STATUSES: tuple[str, ...] = (
    "debited",
    "held_by_risk_control",
    "recalled_returned",
)

DEFAULT_FX_TO_USD: dict[str, str] = {
    "USD": "1.0000",
    "EUR": "1.0850",
    "GBP": "1.2720",
    "HKD": "0.1282",
    "CNY": "0.1385",
    "SGD": "0.7450",
    "JPY": "0.0066",
    "AUD": "0.6580",
    "CAD": "0.7210",
}

MAX_MONETARY_AMOUNT = Decimal("1000000000000.00")

IBAN_LENGTH_BY_COUNTRY: dict[str, int] = {
    "AD": 24, "AE": 23, "AT": 20, "BE": 16, "BG": 22, "CH": 21, "CY": 28,
    "CZ": 24, "DE": 22, "DK": 18, "EE": 20, "ES": 24, "FI": 18, "FR": 27,
    "GB": 22, "GI": 23, "GR": 27, "HR": 21, "HU": 28, "IE": 22, "IL": 23,
    "IS": 26, "IT": 27, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27,
    "MT": 31, "NL": 18, "NO": 15, "PL": 28, "PT": 25, "RO": 24, "SA": 24,
    "SE": 24, "SI": 19, "SK": 24, "SM": 27, "TR": 26, "UA": 29,
}

_IBAN_CANDIDATE_RE = re.compile(
    r"\b([A-Z]{2}[0-9]{2}(?:(?:[ -][A-Z0-9]{4}){2,7}(?:[ -][A-Z0-9]{1,4})?|[A-Z0-9]{11,30}))\b",
    re.IGNORECASE,
)
_CARD_CANDIDATE_RE = re.compile(r"(?<![A-Z0-9])([0-9][0-9 -]{11,22}[0-9])(?![A-Z0-9])")
_BIC_CANDIDATE_RE = re.compile(r"\b([A-Z]{4}[A-Z]{2}[A-Z2-9][A-NP-Z0-9](?:[A-Z0-9]{3})?)\b")
_INVOICE_REF_RE = re.compile(r"\b((?:INV|PO|AWB|SWF|GPI)-[A-Z0-9-]{4,24})\b")
_CSV_FORMULA_PREFIX_RE = re.compile(r"^[\s\x00-\x1f]*[=+\-@|%]")

_COMMON_UPPERCASE_WORDS: frozenset[str] = frozenset({
    "TRANSFER", "REDACTED", "DOCUMENT", "APPROVED", "INTERNAL", "EXTERNAL",
    "CUSTOMER", "MERCHANT", "SECURITY", "EVIDENCE", "CURRENCY", "STANDARD",
    "CRITICAL", "VERIFIED", "DATETIME", "PROTOCOL", "RESPONSE", "BASELINE",
})


@dataclass(frozen=True)
class LedgerEntry:
    tx_id: str
    timestamp_local: str
    utc_offset_hours: float
    category: str
    status: str
    currency: str
    amount: Decimal
    payer_account: str
    beneficiary_name: str
    beneficiary_account: str
    beneficiary_bank: str
    channel_ref: str
    note: str = ""
    explicit_id_provided: bool = False

    def utc_datetime(self) -> datetime:
        return _resolve_utc_datetime(self.timestamp_local, self.utc_offset_hours)


def _validate_utc_offset(raw_offset: Any) -> float:
    if isinstance(raw_offset, bool):
        raise ValueError(f"Invalid UTC offset type: {raw_offset!r}")
    try:
        offset = float(raw_offset)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid UTC offset value: {raw_offset!r}") from exc
    if not math.isfinite(offset) or offset < -12.0 or offset > 14.0:
        raise ValueError(f"UTC offset out of bounds [-12, +14]: {raw_offset!r}")
    return offset


def _has_explicit_utc_suffix(raw: str) -> bool:
    s = raw.strip().upper()
    return s.endswith("Z") or s.endswith(" UTC")


def _resolve_utc_datetime(raw_ts: str, offset_hours: float) -> datetime:
    valid_off = _validate_utc_offset(offset_hours)
    dt = _parse_iso_minutes(raw_ts)
    if _has_explicit_utc_suffix(raw_ts):
        return dt.replace(tzinfo=timezone.utc)
    return dt.replace(tzinfo=timezone(timedelta(hours=valid_off))).astimezone(timezone.utc)


def _parse_iso_minutes(raw: str) -> datetime:
    cleaned = re.sub(r"(?<=\d)[Tt](?=\d)", " ", raw.strip())
    if cleaned.upper().endswith(" UTC"):
        cleaned = cleaned[:-4].strip()
    elif cleaned.upper().endswith("Z"):
        cleaned = cleaned[:-1].strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M"):
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unsupported timestamp format: {raw!r} (expected YYYY-MM-DD HH:MM)")


def _to_decimal(val: Any) -> Decimal:
    if isinstance(val, bool):
        raise ValueError("Boolean is not a valid monetary amount")
    if isinstance(val, Decimal):
        dec = val
    elif isinstance(val, (int, float)):
        if isinstance(val, float) and not math.isfinite(val):
            raise ValueError(f"Monetary amount must be finite: {val!r}")
        try:
            dec = Decimal(str(val))
        except InvalidOperation as exc:
            raise ValueError(f"Invalid monetary amount: {val!r}") from exc
    elif isinstance(val, str):
        stripped = val.strip().replace(",", "").replace(" ", "")
        stripped = re.sub(r"^[$€£¥]", "", stripped)
        if not stripped:
            raise ValueError("Empty monetary amount")
        try:
            dec = Decimal(stripped)
        except InvalidOperation as exc:
            raise ValueError(f"Invalid monetary amount: {val!r}") from exc
    else:
        raise ValueError(f"Unsupported amount type: {type(val).__name__}")
    if not dec.is_finite() or dec < Decimal("0") or dec > MAX_MONETARY_AMOUNT:
        raise ValueError(f"Monetary amount out of valid finite range [0, 1e12]: {val!r}")
    try:
        return dec.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except InvalidOperation as exc:
        raise ValueError(f"Monetary amount cannot be quantized to cents: {val!r}") from exc


def iban_mod97_valid(candidate: str) -> bool:
    """Validate an ISO 13616 International Bank Account Number via ASCII Mod-97-10."""
    compact = re.sub(r"[\s-]+", "", candidate or "").upper()
    if not compact.isascii() or len(compact) < 15 or len(compact) > 34 or not compact.isalnum():
        return False
    cc = compact[:2]
    if not cc.isalpha() or not compact[2:4].isdigit():
        return False
    expected_len = IBAN_LENGTH_BY_COUNTRY.get(cc)
    if expected_len is not None and len(compact) != expected_len:
        return False
    rearranged = compact[4:] + compact[:4]
    digits_buf: list[str] = []
    for ch in rearranged:
        if ch.isdigit():
            digits_buf.append(ch)
        else:
            digits_buf.append(str(ord(ch) - 55))
    rem = 0
    for ch in "".join(digits_buf):
        rem = (rem * 10 + (ord(ch) - 48)) % 97
    return rem == 1


def luhn_valid(candidate: str) -> bool:
    """Validate a 12-to-19-digit ASCII payment account/card number via ISO/IEC 7812 Luhn."""
    digits = re.sub(r"[\s-]+", "", candidate or "")
    if not digits.isascii() or not digits.isdigit() or not (12 <= len(digits) <= 19):
        return False
    if len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for idx, ch in enumerate(digits):
        d = ord(ch) - 48
        if idx % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def swift_bic_valid(candidate: str) -> bool:
    """Validate an 8- or 11-character ISO 9362 SWIFT/BIC institution code."""
    compact = (candidate or "").strip().upper()
    if not compact.isascii() or len(compact) not in (8, 11) or compact in _COMMON_UPPERCASE_WORDS:
        return False
    if not _BIC_CANDIDATE_RE.fullmatch(compact):
        return False
    country = compact[4:6]
    return country in IBAN_LENGTH_BY_COUNTRY or country in {
        "US", "CN", "HK", "SG", "JP", "AU", "CA", "NZ", "KR", "TW", "ZA", "IN", "MX", "BR",
    }


def _mask_identifier(raw: str, key: bytes | None, prefix: str) -> str:
    compact = re.sub(r"\s+", "", raw)
    if key is None:
        if len(compact) <= 8:
            return "****"
        return f"{compact[:4]}****{compact[-4:]}"
    digest = hmac.new(key, compact.encode("utf-8"), hashlib.sha256).hexdigest()[:10]
    return f"[{prefix}-HMAC-{digest}]"


def extract_payment_iocs(
    text: str,
    *,
    redact: bool = False,
    hmac_key: bytes | None = None,
) -> dict[str, Any]:
    """Deterministically extract and checksum-validate IBANs, Luhn accounts, BICs, and refs."""
    if len(text) > 2_000_000:
        raise ValueError("Input text exceeds 2 MB defensive parser bound")

    ibans: list[str] = []
    seen_ibans: set[str] = set()
    for match in _IBAN_CANDIDATE_RE.finditer(text):
        tokens = re.split(r"[\s-]+", match.group(1).upper())
        acc = ""
        for tok in tokens:
            acc += tok
            if iban_mod97_valid(acc):
                if acc not in seen_ibans:
                    seen_ibans.add(acc)
                    ibans.append(_mask_identifier(acc, hmac_key, "IBAN") if redact else acc)
                break

    cards: list[str] = []
    seen_cards: set[str] = set()
    for match in _CARD_CANDIDATE_RE.finditer(text):
        compact = re.sub(r"[\s-]+", "", match.group(1))
        if compact not in seen_cards and luhn_valid(compact):
            seen_cards.add(compact)
            cards.append(_mask_identifier(compact, hmac_key, "ACCT") if redact else compact)

    bics: list[str] = []
    seen_bics: set[str] = set()
    for match in _BIC_CANDIDATE_RE.finditer(text):
        token = match.group(1)
        if token not in seen_bics and swift_bic_valid(token):
            seen_bics.add(token)
            bics.append(token)

    refs: list[str] = []
    seen_refs: set[str] = set()
    for match in _INVOICE_REF_RE.finditer(text.upper()):
        ref = match.group(1)
        if ref not in seen_refs:
            seen_refs.add(ref)
            refs.append(ref)

    return {
        "mod97_ibans": ibans,
        "luhn_accounts": cards,
        "swift_bics": bics,
        "reference_ids": refs,
        "total_validated_iocs": len(ibans) + len(cards) + len(bics) + len(refs),
    }


def check_window_alignment(
    tx_timestamp_local: str,
    tx_utc_offset: float,
    coercion_windows: list[dict[str, Any]],
    *,
    post_window_grace_minutes: int = 30,
) -> dict[str, Any]:
    """Check whether a transaction occurred during or within grace minutes of a coercive call/BEC session."""
    tx_dt = _resolve_utc_datetime(tx_timestamp_local, tx_utc_offset)

    matched: list[dict[str, Any]] = []
    for win in coercion_windows:
        raw_w_off = win.get("utc_offset_hours", win.get("utcOffset", win.get("offset", 0.0)))
        start_str = str(win.get("start_local", win.get("startLocal", "")))
        end_str = str(win.get("end_local", win.get("endLocal", "")))
        start_utc = _resolve_utc_datetime(start_str, raw_w_off)
        end_utc = _resolve_utc_datetime(end_str, raw_w_off)
        if end_utc < start_utc:
            end_utc, start_utc = start_utc, end_utc
        grace_end = end_utc + timedelta(minutes=max(0, post_window_grace_minutes))
        win_id = str(win.get("window_id", win.get("id", "WIN")))
        win_ch = str(win.get("channel", "session"))
        if start_utc <= tx_dt <= end_utc:
            matched.append({
                "window_id": win_id,
                "channel": win_ch,
                "alignment": "DURING_ACTIVE_SESSION",
                "offset_minutes_from_end": 0,
            })
        elif end_utc < tx_dt <= grace_end:
            delta_min = int((tx_dt - end_utc).total_seconds() // 60)
            matched.append({
                "window_id": win_id,
                "channel": win_ch,
                "alignment": "POST_SESSION_IMMEDIATE",
                "offset_minutes_from_end": delta_min,
            })

    return {
        "tx_utc_iso": tx_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "aligned": bool(matched),
        "matches": matched,
    }


def normalize_entry(raw: dict[str, Any], index: int = 1) -> LedgerEntry:
    """Normalize a transaction dict (accepting both CLI snake_case and Web camelCase keys)."""
    category = str(raw.get("category", "external_beneficiary")).strip()
    if category not in VALID_CATEGORIES:
        raise ValueError(f"Unsupported transaction category: {category!r}; expected one of {VALID_CATEGORIES}")

    status = str(raw.get("status", "debited")).strip()
    if status not in VALID_STATUSES:
        raise ValueError(f"Unsupported transaction status: {status!r}; expected one of {VALID_STATUSES}")

    currency = str(raw.get("currency", "USD")).strip().upper()
    if not (currency.isascii() and len(currency) == 3 and currency.isalpha()):
        raise ValueError(f"Invalid ISO 4217 currency code: {currency!r}")

    raw_offset = raw.get("utc_offset_hours", raw.get("utcOffset", raw.get("offset", 0.0)))
    offset = _validate_utc_offset(raw_offset)

    ts_raw = raw.get("timestamp_local", raw.get("timestampLocal"))
    if ts_raw is None:
        raise ValueError("Missing transaction timestamp ('timestamp_local' or 'timestampLocal')")

    if "amount" not in raw:
        raise ValueError("Missing transaction 'amount'")

    tx_id_raw = raw.get("tx_id", raw.get("id"))
    has_explicit_id = bool(
        tx_id_raw is not None and str(tx_id_raw).strip() and not raw.get("_auto_id", False)
    )
    entry = LedgerEntry(
        tx_id=str(tx_id_raw if tx_id_raw is not None and str(tx_id_raw).strip() else f"TX-{index:03d}").strip(),
        timestamp_local=str(ts_raw).strip(),
        utc_offset_hours=0.0 if _has_explicit_utc_suffix(str(ts_raw)) else offset,
        category=category,
        status=status,
        currency=currency,
        amount=_to_decimal(raw["amount"]),
        payer_account=str(raw.get("payer_account", raw.get("payerAccount", ""))).strip(),
        beneficiary_name=str(
            raw.get("beneficiary_name", raw.get("beneficiaryName", raw.get("beneficiary", "")))
        ).strip(),
        beneficiary_account=str(raw.get("beneficiary_account", raw.get("beneficiaryAccount", ""))).strip(),
        beneficiary_bank=str(raw.get("beneficiary_bank", raw.get("beneficiaryBank", ""))).strip(),
        channel_ref=str(raw.get("channel_ref", raw.get("channelRef", ""))).strip(),
        note=str(raw.get("note", raw.get("notes", ""))).strip(),
        explicit_id_provided=has_explicit_id,
    )
    entry.utc_datetime()
    return entry


def _parse_fx_rate_map(fx_to_usd: dict[str, str | float] | None) -> dict[str, Decimal]:
    rates: dict[str, Decimal] = {k: Decimal(v) for k, v in DEFAULT_FX_TO_USD.items()}
    if fx_to_usd:
        for cur, val in fx_to_usd.items():
            code = str(cur).strip().upper()
            if not (code.isascii() and len(code) == 3 and code.isalpha()):
                raise ValueError(f"Invalid currency code in FX rate map: {cur!r}")
            if isinstance(val, bool):
                raise ValueError(f"Invalid FX rate for {code}: {val!r}")
            try:
                dec_rate = Decimal(str(val))
            except InvalidOperation as exc:
                raise ValueError(f"Non-numeric FX rate for {code}: {val!r}") from exc
            if not dec_rate.is_finite() or dec_rate <= Decimal("0"):
                raise ValueError(f"FX rate for {code} must be finite and strictly positive: {val!r}")
            rates[code] = dec_rate
    return rates


def compute_ledger_exposure(
    raw_entries: list[dict[str, Any]],
    *,
    coercion_windows: list[dict[str, Any]] | None = None,
    fx_to_usd: dict[str, str | float] | None = None,
    base_currency: str = "USD",
    redact_payer_accounts: bool = False,
    hmac_key: bytes | None = None,
) -> dict[str, Any]:
    """Compute de-duplicated net exposure, stripping internal FX transit, risk-held, and duplicate rows."""
    rates = _parse_fx_rate_map(fx_to_usd)
    base_cur = base_currency.strip().upper()
    if base_cur not in rates or rates[base_cur] <= Decimal("0"):
        raise ValueError(f"Missing positive FX rate for base_currency={base_cur!r}")

    entries = [normalize_entry(item, idx + 1) for idx, item in enumerate(raw_entries)]
    entries.sort(key=lambda e: (e.utc_datetime(), e.tx_id))

    def convert_to_base(amount: Decimal, cur: str) -> Decimal:
        if cur == base_cur:
            return amount
        if cur not in rates:
            raise ValueError(f"Missing FX rate for transaction currency {cur!r}")
        usd_val = amount * rates[cur]
        return (usd_val / rates[base_cur]).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    gross_touched = Decimal("0.00")
    net_external_wire = Decimal("0.00")
    net_asset_diversion = Decimal("0.00")
    stripped_internal_transit = Decimal("0.00")
    held_frozen_pool = Decimal("0.00")
    recalled_returned_pool = Decimal("0.00")
    excluded_duplicates = Decimal("0.00")
    currency_totals: dict[str, Decimal] = {}

    seen_exact_fps: set[tuple[str, ...]] = set()
    seen_loose_fps: set[tuple[str, str, str, str]] = set()
    duplicate_warnings: list[str] = []
    normalized_rows: list[dict[str, Any]] = []

    for entry in entries:
        utc_dt = entry.utc_datetime()
        utc_sec = utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        utc_min = utc_dt.strftime("%Y-%m-%dT%H:%MZ")
        norm_payer = re.sub(r"[\s-]+", "", entry.payer_account).upper()
        norm_acct = re.sub(r"[\s-]+", "", entry.beneficiary_account).upper()
        amt_str = f"{entry.amount:.2f}"
        exact_fp = (
            entry.tx_id if entry.explicit_id_provided else "",
            utc_sec,
            entry.category,
            entry.status,
            entry.currency,
            amt_str,
            norm_payer,
            entry.beneficiary_name.lower(),
            norm_acct,
            entry.beneficiary_bank.lower(),
            entry.channel_ref.lower(),
            entry.note,
        )
        loose_fp = (utc_min, entry.currency, amt_str, norm_acct)

        base_equiv = convert_to_base(entry.amount, entry.currency)
        gross_touched += base_equiv

        if exact_fp in seen_exact_fps:
            duplicate_warnings.append(
                f"Excluded exact duplicate ledger entry {entry.tx_id} ({entry.currency} {amt_str} -> {entry.beneficiary_account})"
            )
            excluded_duplicates += base_equiv
            inclusion_bucket = "EXCLUDED_DUPLICATE"
        else:
            seen_exact_fps.add(exact_fp)
            if loose_fp in seen_loose_fps:
                duplicate_warnings.append(
                    f"Same-minute/amount counterparty match across statuses on {entry.tx_id} ({entry.currency} {amt_str} -> {entry.beneficiary_account})"
                )
            seen_loose_fps.add(loose_fp)

            inclusion_bucket = "EXCLUDED"
            if entry.status == "held_by_risk_control":
                held_frozen_pool += base_equiv
                inclusion_bucket = "EXCLUDED_RISK_HELD"
            elif entry.status == "recalled_returned":
                recalled_returned_pool += base_equiv
                inclusion_bucket = "EXCLUDED_RECALLED"
            elif entry.category == "internal_transit":
                stripped_internal_transit += base_equiv
                inclusion_bucket = "EXCLUDED_INTERNAL_TRANSIT"
            elif entry.category == "external_beneficiary":
                net_external_wire += base_equiv
                currency_totals[entry.currency] = currency_totals.get(entry.currency, Decimal("0.00")) + entry.amount
                inclusion_bucket = "INCLUDED_NET_EXTERNAL_WIRE"
            elif entry.category == "asset_diversion":
                net_asset_diversion += base_equiv
                currency_totals[entry.currency] = currency_totals.get(entry.currency, Decimal("0.00")) + entry.amount
                inclusion_bucket = "INCLUDED_NET_ASSET_DIVERSION"

        alignment = check_window_alignment(
            entry.timestamp_local,
            entry.utc_offset_hours,
            coercion_windows or [],
        )
        row = asdict(entry)
        row.pop("explicit_id_provided", None)
        row["amount"] = amt_str
        row["base_currency_equivalent"] = f"{base_equiv:.2f}"
        row["utc_iso"] = alignment["tx_utc_iso"]
        row["session_aligned"] = alignment["aligned"]
        row["session_matches"] = alignment["matches"]
        row["inclusion_bucket"] = inclusion_bucket
        row["beneficiary_iban_valid"] = iban_mod97_valid(entry.beneficiary_account)
        row["beneficiary_luhn_valid"] = luhn_valid(entry.beneficiary_account)
        if redact_payer_accounts and row["payer_account"]:
            row["payer_account"] = _mask_identifier(row["payer_account"], hmac_key, "PAYER")
        normalized_rows.append(row)

    net_total = (net_external_wire + net_asset_diversion).quantize(Decimal("0.01"))
    return {
        "base_currency": base_cur,
        "summary": {
            "total_records": len(entries),
            "gross_volume_touched": f"{gross_touched:.2f}",
            "net_verified_exposure": f"{net_total:.2f}",
            "net_external_beneficiary_wire": f"{net_external_wire:.2f}",
            "net_diverted_settlement": f"{net_asset_diversion:.2f}",
            "stripped_internal_transit_fx": f"{stripped_internal_transit:.2f}",
            "excluded_risk_control_held": f"{held_frozen_pool:.2f}",
            "excluded_recalled_returned": f"{recalled_returned_pool:.2f}",
            "excluded_duplicate_entries": f"{excluded_duplicates:.2f}",
            "net_exposure_by_original_currency": {
                k: f"{v:.2f}" for k, v in sorted(currency_totals.items())
            },
        },
        "duplicate_warnings": duplicate_warnings,
        "transactions": normalized_rows,
    }


def sanitize_csv_cell(val: Any) -> str:
    """Neutralize spreadsheet formula injection (CWE-1236) including leading whitespace/control chars."""
    s = "" if val is None else str(val)
    s = s.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    if _CSV_FORMULA_PREFIX_RE.match(s) or s.startswith("\t"):
        s = "'" + s
    return s


def export_ledger_csv(report: dict[str, Any]) -> str:
    """Serialize a computed ledger report into an OWASP CWE-1236 hardened UTF-8 CSV string."""
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow([
        "UTC_Timestamp", "Category", "Status", "Currency", "Amount",
        "Base_Currency", "Base_Equivalent", "Inclusion_Bucket",
        "Payer_Account", "Beneficiary_Name", "Beneficiary_Account", "Bank_Ref", "Note",
    ])
    base_ccy = report.get("base_currency", "USD")
    for tx in report.get("transactions", []):
        writer.writerow([
            sanitize_csv_cell(tx.get("utc_iso", "")),
            sanitize_csv_cell(tx.get("category", "")),
            sanitize_csv_cell(tx.get("status", "")),
            sanitize_csv_cell(tx.get("currency", "")),
            sanitize_csv_cell(tx.get("amount", "0.00")),
            sanitize_csv_cell(base_ccy),
            sanitize_csv_cell(tx.get("base_currency_equivalent", "0.00")),
            sanitize_csv_cell(tx.get("inclusion_bucket", "")),
            sanitize_csv_cell(tx.get("payer_account", "")),
            sanitize_csv_cell(tx.get("beneficiary_name", "")),
            sanitize_csv_cell(tx.get("beneficiary_account", "")),
            sanitize_csv_cell(tx.get("beneficiary_bank", "")),
            sanitize_csv_cell(tx.get("note", "")),
        ])
    return buf.getvalue()


def parse_tabular_transactions(tabular_text: str) -> list[dict[str, Any]]:
    """Parse pasted RFC 4180 CSV or TSV bank ledger lines into structured transaction dicts."""
    raw = tabular_text.lstrip("\ufeff").strip()
    if not raw:
        return []
    first_line = next((ln for ln in raw.splitlines() if ln.strip()), "")
    delim = "\t" if "\t" in first_line else ","
    if "\x00" in raw:
        raise ValueError("Malformed CSV/TSV input: NUL byte not permitted")
    try:
        parsed_rows = [
            [col.strip() for col in row]
            for row in csv.reader(io.StringIO(raw, newline=""), delimiter=delim)
            if any(col.strip() for col in row)
        ]
    except csv.Error as exc:
        raise ValueError(f"Malformed CSV/TSV input: {exc}") from exc
    if not parsed_rows:
        return []

    start_idx = 0
    first_cols = [c.lower() for c in parsed_rows[0]]
    if any(
        h in first_cols
        for h in ("timestamp", "utc_timestamp", "date", "time", "amount", "时间", "金额")
    ):
        start_idx = 1

    rows: list[dict[str, Any]] = []
    for idx, cols in enumerate(parsed_rows[start_idx:], 1):
        if len(cols) < 4:
            raise ValueError(f"Row {idx} has fewer than 4 columns: {cols!r}")

        if len(cols) == 4:
            rows.append({
                "tx_id": f"IMP-{idx:03d}",
                "_auto_id": True,
                "timestamp_local": cols[0],
                "utc_offset_hours": 0.0 if _has_explicit_utc_suffix(cols[0]) else 8.0,
                "currency": "USD",
                "amount": cols[1],
                "category": "external_beneficiary",
                "status": "debited",
                "beneficiary_name": cols[2],
                "beneficiary_account": cols[3],
            })
        elif len(cols) in (5, 6):
            rows.append({
                "tx_id": f"IMP-{idx:03d}",
                "_auto_id": True,
                "timestamp_local": cols[0],
                "utc_offset_hours": 0.0 if _has_explicit_utc_suffix(cols[0]) else 8.0,
                "currency": cols[1].upper(),
                "amount": cols[2],
                "category": "external_beneficiary",
                "status": "debited",
                "beneficiary_name": cols[3],
                "beneficiary_account": cols[4],
                "beneficiary_bank": cols[5] if len(cols) == 6 else "",
            })
        elif len(cols) >= 12 and cols[1] in VALID_CATEGORIES and cols[2] in VALID_STATUSES:
            has_bucket = len(cols) >= 13
            shift = 1 if has_bucket else 0
            rows.append({
                "tx_id": f"IMP-{idx:03d}",
                "_auto_id": True,
                "timestamp_local": cols[0],
                "utc_offset_hours": 0.0,
                "category": cols[1],
                "status": cols[2],
                "currency": cols[3].upper(),
                "amount": cols[4],
                "payer_account": cols[7 + shift],
                "beneficiary_name": cols[8 + shift],
                "beneficiary_account": cols[9 + shift],
                "beneficiary_bank": cols[10 + shift],
                "note": cols[11 + shift] if len(cols) > 11 + shift else "",
            })
        else:
            if len(cols) < 8:
                raise ValueError(
                    f"Row {idx} must have 4, 5, 6, 8+, or 12+ columns (got {len(cols)}): {cols!r}"
                )
            rows.append({
                "tx_id": f"IMP-{idx:03d}",
                "_auto_id": True,
                "timestamp_local": cols[0],
                "utc_offset_hours": 0.0 if _has_explicit_utc_suffix(cols[0]) else _validate_utc_offset(cols[1]),
                "currency": cols[2].upper(),
                "amount": cols[3],
                "category": cols[4],
                "status": cols[5],
                "beneficiary_name": cols[6],
                "beneficiary_account": cols[7],
                "beneficiary_bank": cols[8] if len(cols) >= 9 else "",
            })
    return rows


def build_synthetic_bec_incident() -> dict[str, Any]:
    """Return a 100% synthetic cross-border BEC & executive impersonation triage dataset."""
    return {
        "case_ref": "SYN-BEC-2026-041",
        "synthetic_notice": "100% SYNTHETIC BENCHMARK DATA (Apex Maritime GmbH) — ZERO REAL PII",
        "entity_name": "Apex Maritime GmbH (Treasury Ops)",
        "reporting_jurisdiction": "Frankfurt / Hong Kong SWIFT gpi Recall Desk",
        "coercion_windows": [
            {
                "window_id": "BEC-CALL-01",
                "channel": "Spoofed Thread + Deepfake Voice Callback",
                "start_local": "2026-05-14 09:15",
                "end_local": "2026-05-14 10:40",
                "utc_offset_hours": 2.0,
            }
        ],
        "transactions": [
            {
                "tx_id": "SYN-TX-01",
                "timestamp_local": "2026-05-14 09:32",
                "utc_offset_hours": 2.0,
                "category": "internal_transit",
                "status": "debited",
                "currency": "EUR",
                "amount": "22000.00",
                "payer_account": "DE89370400440532013000",
                "beneficiary_name": "Apex Maritime GmbH Multi-Currency Treasury",
                "beneficiary_account": "GB82WEST12345698765432",
                "beneficiary_bank": "NWBKGB2L (Internal FX Liquidity Sweep)",
                "channel_ref": "SWF-INT-20260514-01",
                "note": "Internal same-entity EUR->HKD liquidity conversion; must be excluded from net loss.",
            },
            {
                "tx_id": "SYN-TX-02",
                "timestamp_local": "2026-05-14 16:05",
                "utc_offset_hours": 8.0,
                "category": "external_beneficiary",
                "status": "debited",
                "currency": "HKD",
                "amount": "165000.00",
                "payer_account": "GB82WEST12345698765432",
                "beneficiary_name": "Harborline Bunker Supply Co (Impersonated)",
                "beneficiary_account": "4532015112830366",
                "beneficiary_bank": "Demo Clearing Bank HK (SWIFT: HSBCHKHH)",
                "channel_ref": "GPI-994021-A",
                "note": "Fraudulent amended invoice INV-2026-8841 settled during spoofed callback window.",
            },
            {
                "tx_id": "SYN-TX-03",
                "timestamp_local": "2026-05-14 16:48",
                "utc_offset_hours": 8.0,
                "category": "external_beneficiary",
                "status": "held_by_risk_control",
                "currency": "HKD",
                "amount": "48000.00",
                "payer_account": "GB82WEST12345698765432",
                "beneficiary_name": "Harborline Bunker Supply Co (Impersonated)",
                "beneficiary_account": "6200000000000005",
                "beneficiary_bank": "Demo Commercial Bank",
                "channel_ref": "GPI-994022-HOLD",
                "note": "Paused by outbound bank velocity rule prior to Nostro settlement; held in suspense.",
            },
        ],
    }
