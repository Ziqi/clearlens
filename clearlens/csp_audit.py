# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""Zero-Backend Offline CSP & External-Asset Security Auditor (`clearlens.csp_audit`).

Verifies that static HTML workbenches deployed to GitHub Pages or distributed as air-gapped ZIP
bundles strictly enforce offline-first Content-Security-Policy (`default-src 'none'`), contain
zero external scripts, stylesheets, fonts, frames, or telemetry beacons, and preserve user privacy.
"""

from __future__ import annotations

from html.parser import HTMLParser
import os
from pathlib import Path
import re
from typing import Any

ALLOWED_LOOPBACK_CONNECT_ORIGINS: frozenset[str] = frozenset({
    "'none'",
    "http://127.0.0.1:11434",
    "http://localhost:11434",
})

ALLOWED_IMG_SRC_TOKENS: frozenset[str] = frozenset({"'none'", "'self'", "blob:", "data:"})
ALLOWED_INLINE_CODE_TOKENS: frozenset[str] = frozenset({"'none'", "'self'", "'unsafe-inline'"})

_EXTERNAL_URL_IN_CSS_RE = re.compile(r"url\(\s*['\"]?\s*(https?:|wss?:|//)", re.IGNORECASE)
_ALLOWED_LOOPBACK_FETCH_URL_RE = re.compile(
    r"^http://(?:127\.0\.0\.1|localhost):11434/[A-Za-z0-9_./-]+$"
)
_FORBIDDEN_JS_IDENTIFIERS: frozenset[str] = frozenset({
    "XMLHttpRequest",
    "WebSocket",
    "EventSource",
    "sendBeacon",
    "Worker",
    "SharedWorker",
    "ServiceWorker",
    "eval",
    "Function",
    "import",
})
_FORBIDDEN_GLOBAL_BRACKET_OBJECTS: frozenset[str] = frozenset({
    "window",
    "self",
    "globalThis",
    "top",
    "parent",
    "frames",
})
_REMOTE_SCHEME_PREFIXES: tuple[str, ...] = ("http://", "https://", "//", "ws://", "wss://")


def _tokenize_js_for_audit(js: str) -> list[tuple[str, str]]:
    """Single-pass JS lexer stripping comments and yielding ('id'|'str'|'tpl'|'punct', value)."""
    tokens: list[tuple[str, str]] = []
    n = len(js)
    i = 0
    while i < n:
        ch = js[i]
        if ch in " \t\r\n\f\v":
            i += 1
            continue
        if ch == "/" and i + 1 < n and js[i + 1] == "/":
            nl = js.find("\n", i + 2)
            i = n if nl == -1 else nl + 1
            continue
        if ch == "/" and i + 1 < n and js[i + 1] == "*":
            end = js.find("*/", i + 2)
            if end == -1:
                tokens.append(("punct", "unclosed_comment"))
                break
            i = end + 2
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            buf: list[str] = []
            while i < n:
                c = js[i]
                if c == "\\":
                    if i + 1 < n:
                        buf.append(js[i + 1])
                        i += 2
                        continue
                    i += 1
                    break
                if c == quote:
                    i += 1
                    break
                buf.append(c)
                i += 1
            tokens.append(("str", "".join(buf)))
            continue
        if ch == "`":
            i += 1
            buf_t: list[str] = []
            while i < n:
                c = js[i]
                if c == "\\":
                    i += 2
                    continue
                if c == "`":
                    i += 1
                    break
                buf_t.append(c)
                i += 1
            tokens.append(("tpl", "".join(buf_t)))
            continue
        if ch.isalpha() or ch in ("_", "$"):
            start = i
            i += 1
            while i < n and (js[i].isalnum() or js[i] in ("_", "$")):
                i += 1
            tokens.append(("id", js[start:i]))
            continue
        tokens.append(("punct", ch))
        i += 1
    return tokens


def _scan_js_network_sinks(js_block: str) -> list[str]:
    """Fail-closed lexical verifier rejecting direct, aliased, `.call`/`.apply`, or bracket network sinks."""
    findings: list[str] = []
    toks = _tokenize_js_for_audit(js_block)
    total = len(toks)
    for idx, (kind, val) in enumerate(toks):
        if kind == "punct" and val == "unclosed_comment":
            findings.append("Unclosed multiline comment inside inline <script>.")
            continue
        if kind == "str" and val in (_FORBIDDEN_JS_IDENTIFIERS | {"fetch"}):
            if idx > 0 and toks[idx - 1] == ("punct", "["):
                findings.append(f"Bracket property access to network/eval sink forbidden: [{val!r}]")
        if kind == "tpl" and "${" in val and any(s in val for s in ("http:", "https:", "ws:", "wss:", "fetch")):
            findings.append("Dynamic template literal URL/sink forbidden inside inline <script>.")
        if kind != "id":
            continue
        if val in _FORBIDDEN_JS_IDENTIFIERS:
            findings.append(f"Forbidden network/dynamic-code identifier inside inline <script>: {val}")
            continue
        if val in _FORBIDDEN_GLOBAL_BRACKET_OBJECTS and idx + 1 < total and toks[idx + 1] == ("punct", "["):
            findings.append(f"Computed bracket lookup on global object forbidden: {val}[...]")
            continue
        if val == "fetch":
            # Fail-closed: EVERY `fetch` token must be a direct call `fetch("http://127.0.0.1:11434/...", ...)`
            # Aliases (`const f = fetch`), `.call`/`.apply` (`fetch.call(...)`), or dynamic args fail immediately.
            if (
                idx + 3 >= total
                or toks[idx + 1] != ("punct", "(")
                or toks[idx + 2][0] != "str"
                or not _ALLOWED_LOOPBACK_FETCH_URL_RE.match(toks[idx + 2][1])
                or toks[idx + 3] not in (("punct", ","), ("punct", ")"))
            ):
                findings.append(
                    "Disallowed, aliased, or non-literal fetch reference inside inline <script> "
                    "(only direct literal loopback fetch('http://127.0.0.1:11434/...') is permitted)."
                )
    return findings


class _OfflineHTMLInspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.csp_policies: list[str] = []
        self.meta_refresh_tags: list[str] = []
        self.duplicate_attributes: list[dict[str, str]] = []
        self.external_refs: list[dict[str, str]] = []
        self.inline_styles: list[str] = []
        self.inline_scripts: list[str] = []
        self._active_tag: str | None = None
        self._buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_l = tag.lower()
        # Per WHATWG HTML §13.2.5.33, browsers keep the FIRST attribute and ignore duplicates;
        # we both preserve first-wins semantics AND record any duplicate attribute as a violation.
        attr_map: dict[str, str] = {}
        for k, v in attrs:
            k_l = k.lower()
            val_s = v or ""
            if k_l in attr_map:
                self.duplicate_attributes.append({"tag": tag_l, "attribute": k_l})
            else:
                attr_map[k_l] = val_s

        if tag_l == "meta":
            http_equiv = attr_map.get("http-equiv", "").strip().lower()
            if http_equiv == "content-security-policy":
                self.csp_policies.append(attr_map.get("content", "").strip())
            elif http_equiv == "refresh":
                self.meta_refresh_tags.append(attr_map.get("content", "").strip())

        for raw_k, raw_v in attrs:
            attr_name = raw_k.lower()
            val = (raw_v or "").strip()
            if not val:
                continue
            if attr_name in ("src", "href", "action", "formaction", "poster", "data", "ping"):
                if tag_l == "a" and attr_name == "href":
                    continue
                if val.lower().startswith(_REMOTE_SCHEME_PREFIXES):
                    self.external_refs.append({
                        "tag": tag_l,
                        "attribute": attr_name,
                        "url": val,
                    })
            elif attr_name in ("srcset", "imagesrcset"):
                for candidate in val.split(","):
                    parts = candidate.strip().split()
                    if parts and parts[0].lower().startswith(_REMOTE_SCHEME_PREFIXES):
                        self.external_refs.append({
                            "tag": tag_l,
                            "attribute": attr_name,
                            "url": parts[0],
                        })

        if tag_l in ("style", "script"):
            self._active_tag = tag_l
            self._buf = []

    def handle_data(self, data: str) -> None:
        if self._active_tag is not None:
            self._buf.append(data)

    def handle_endtag(self, tag: str) -> None:
        tag_l = tag.lower()
        if self._active_tag == tag_l:
            joined = "".join(self._buf)
            if tag_l == "style":
                self.inline_styles.append(joined)
            elif tag_l == "script":
                self.inline_scripts.append(joined)
            self._active_tag = None
            self._buf = []


def _parse_csp_directives(csp: str) -> tuple[dict[str, list[str]], list[str]]:
    """Parse CSP directives per W3C CSP3 §6.1 (first directive wins; duplicates flagged)."""
    directives: dict[str, list[str]] = {}
    duplicates: list[str] = []
    for chunk in csp.split(";"):
        tokens = chunk.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name in directives:
            duplicates.append(name)
            # Per W3C CSP3 spec, browsers ignore subsequent duplicate directives; keep first!
            continue
        directives[name] = tokens[1:]
    return directives, duplicates


def _validate_single_csp_policy(csp: str, violations: list[str]) -> None:
    directives, duplicates = _parse_csp_directives(csp)
    if duplicates:
        violations.append(f"Duplicate CSP directive(s) forbidden: {duplicates!r}.")

    default_src = directives.get("default-src", [])
    if default_src != ["'none'"]:
        violations.append(f"CSP default-src must be strictly \"'none'\" (found: {default_src!r}).")

    base_uri = directives.get("base-uri", [])
    if base_uri != ["'none'"]:
        violations.append(f"CSP base-uri must be \"'none'\" (found: {base_uri!r}).")

    form_action = directives.get("form-action", [])
    if form_action != ["'none'"]:
        violations.append(f"CSP form-action must be \"'none'\" (found: {form_action!r}).")

    for dir_name, values in directives.items():
        if dir_name in ("default-src", "base-uri", "form-action"):
            continue
        if dir_name == "connect-src":
            bad = [o for o in values if o not in ALLOWED_LOOPBACK_CONNECT_ORIGINS]
            if bad or not values:
                violations.append(f"CSP connect-src permits non-loopback origins: {values!r}.")
        elif dir_name == "img-src":
            bad = [o for o in values if o not in ALLOWED_IMG_SRC_TOKENS]
            if bad or not values:
                violations.append(f"CSP img-src permits remote/disallowed sources: {values!r}.")
        elif dir_name in ("script-src", "style-src"):
            bad = [o for o in values if o not in ALLOWED_INLINE_CODE_TOKENS]
            if bad or not values:
                violations.append(f"CSP {dir_name} permits remote/disallowed sources: {values!r}.")
        else:
            if values != ["'none'"]:
                violations.append(
                    f"CSP directive {dir_name!r} must be \"'none'\" or omitted under default-src 'none' (found: {values!r})."
                )


def audit_html_content(html_text: str, *, label: str = "<memory>") -> dict[str, Any]:
    """Audit raw HTML string for strict zero-backend offline CSP and zero external subresources."""
    if len(html_text) > 10_000_000:
        raise ValueError("HTML input exceeds 10 MB defensive audit bound")

    inspector = _OfflineHTMLInspector()
    inspector.feed(html_text)
    inspector.close()

    violations: list[str] = []
    if not inspector.csp_policies:
        violations.append("Missing <meta http-equiv=\"Content-Security-Policy\"> header tag.")
    else:
        for policy in inspector.csp_policies:
            _validate_single_csp_policy(policy, violations)

    for dup_attr in inspector.duplicate_attributes:
        violations.append(
            f"Duplicate HTML attribute forbidden on <{dup_attr['tag']}>: {dup_attr['attribute']!r}."
        )

    for refresh in inspector.meta_refresh_tags:
        violations.append(f"Forbidden <meta http-equiv=\"refresh\"> redirect tag: {refresh!r}.")

    for ext in inspector.external_refs:
        violations.append(
            f"External subresource forbidden in zero-backend bundle: <{ext['tag']} {ext['attribute']}=\"{ext['url']}\">"
        )

    for css_block in inspector.inline_styles:
        if _EXTERNAL_URL_IN_CSS_RE.search(css_block):
            violations.append("External CSS url(http/https/ws) reference detected inside inline <style>.")

    for js_block in inspector.inline_scripts:
        violations.extend(_scan_js_network_sinks(js_block))

    return {
        "file": label,
        "passed": len(violations) == 0,
        "csp_present": bool(inspector.csp_policies),
        "csp_policy": inspector.csp_policies[0] if inspector.csp_policies else "",
        "external_subresources_count": len(inspector.external_refs),
        "inline_script_blocks": len(inspector.inline_scripts),
        "inline_style_blocks": len(inspector.inline_styles),
        "violations": violations,
    }


def audit_html_file(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        return {
            "file": str(path),
            "passed": False,
            "csp_present": False,
            "csp_policy": "",
            "external_subresources_count": 0,
            "inline_script_blocks": 0,
            "inline_style_blocks": 0,
            "violations": [f"Symlink HTML file forbidden in web bundle: {path}"],
        }
    data = path.read_text(encoding="utf-8")
    return audit_html_content(data, label=str(path))


def audit_web_directory(web_dir: Path) -> dict[str, Any]:
    if not web_dir.exists() or not web_dir.is_dir():
        raise FileNotFoundError(f"Web bundle directory not found: {web_dir}")
    if web_dir.is_symlink():
        return {
            "directory": str(web_dir),
            "html_files_checked": 0,
            "symlink_violations": [str(web_dir)],
            "all_passed": False,
            "reports": [],
        }

    root_resolved = web_dir.resolve()
    symlink_violations: list[str] = []
    html_files: list[Path] = []
    for cur_root, dirnames, filenames in os.walk(web_dir, followlinks=False):
        cur_p = Path(cur_root)
        for d in list(dirnames):
            dp = cur_p / d
            if dp.is_symlink() or not dp.resolve().is_relative_to(root_resolved):
                symlink_violations.append(str(dp))
                dirnames.remove(d)
        for fn in filenames:
            fp = cur_p / fn
            if fp.is_symlink() or not fp.resolve().is_relative_to(root_resolved):
                symlink_violations.append(str(fp))
            elif fp.suffix.lower() == ".html":
                html_files.append(fp)

    html_files.sort()
    if not html_files and not symlink_violations:
        raise ValueError(f"No .html files found inside {web_dir}")

    reports = [audit_html_file(p) for p in html_files]
    all_passed = (len(symlink_violations) == 0) and bool(reports) and all(r["passed"] for r in reports)
    result: dict[str, Any] = {
        "directory": str(web_dir),
        "html_files_checked": len(reports),
        "all_passed": all_passed,
        "reports": reports,
    }
    if symlink_violations:
        result["symlink_violations"] = symlink_violations
    return result
