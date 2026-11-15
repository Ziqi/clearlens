#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""Bit-for-bit reproducible offline ZIP bundle & Python zipapp builder for ClearLens.

Normalizes file ordering, UNIX permissions, line endings, and ZIP timestamps (2026-01-01 00:00:00 UTC)
so repeated builds from identical source trees yield identical SHA-256 digests (`build_repeatable`).
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import zipfile

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXED_ZIP_DT = (2026, 1, 1, 0, 0, 0)
SHEBANG = b"#!/usr/bin/env python3\n"
ENTRYPOINT_MAIN = (
    "# -*- coding: utf-8 -*-\n"
    "from clearlens.cli import main\n"
    "if __name__ == '__main__':\n"
    "    raise SystemExit(main())\n"
).encode("utf-8")


def _write_deterministic_entry(zf: zipfile.ZipFile, arcname: str, data: bytes) -> None:
    info = zipfile.ZipInfo(arcname, date_time=FIXED_ZIP_DT)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    info.create_system = 3
    zf.writestr(info, data)


def build_offline_web_zip(out_zip: Path, version: str = "1.0.0") -> str:
    """Build deterministic air-gapped ClearLens web distribution ZIP."""
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    prefix = f"clearlens-offline-v{version}"
    candidates = [
        REPO_ROOT / "web" / "index.html",
        REPO_ROOT / "web" / "app.html",
        REPO_ROOT / "LICENSE",
        REPO_ROOT / "README.md",
        REPO_ROOT / "README.zh-CN.md",
        REPO_ROOT / "SECURITY.md",
    ]
    with zipfile.ZipFile(out_zip, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(candidates, key=lambda p: p.relative_to(REPO_ROOT).as_posix()):
            if not path.is_file():
                continue
            rel = path.relative_to(REPO_ROOT).as_posix()
            raw = path.read_bytes().replace(b"\r\n", b"\n")
            _write_deterministic_entry(zf, f"{prefix}/{rel}", raw)
    return hashlib.sha256(out_zip.read_bytes()).hexdigest()


def build_deterministic_pyz(out_pyz: Path) -> str:
    """Build deterministic single-file executable Python zipapp (`clearlens.pyz`)."""
    pkg_dir = REPO_ROOT / "clearlens"
    source_files = sorted(
        p
        for p in pkg_dir.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and not p.name.endswith(".pyc")
    )
    out_pyz.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_zip = Path(tmp.name)

    try:
        with zipfile.ZipFile(tmp_zip, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            _write_deterministic_entry(zf, "__main__.py", ENTRYPOINT_MAIN)
            for src in source_files:
                rel = src.relative_to(REPO_ROOT).as_posix()
                raw = src.read_bytes().replace(b"\r\n", b"\n")
                _write_deterministic_entry(zf, rel, raw)
        payload = SHEBANG + tmp_zip.read_bytes()
        out_pyz.write_bytes(payload)
        return hashlib.sha256(payload).hexdigest()
    finally:
        tmp_zip.unlink(missing_ok=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Build reproducible ClearLens offline ZIP and PYZ artifacts")
    ap.add_argument("--dist-dir", type=Path, default=REPO_ROOT / "dist")
    ap.add_argument("--version", type=str, default="1.0.0")
    ap.add_argument("--verify", action="store_true", help="Build twice and assert identical SHA-256 digests")
    args = ap.parse_args()

    zip_path = args.dist_dir / f"clearlens-offline-v{args.version}.zip"
    pyz_path = args.dist_dir / "clearlens.pyz"

    zip_sha1 = build_offline_web_zip(zip_path, version=args.version)
    pyz_sha1 = build_deterministic_pyz(pyz_path)

    if args.verify:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            zip_sha2 = build_offline_web_zip(td_path / zip_path.name, version=args.version)
            pyz_sha2 = build_deterministic_pyz(td_path / pyz_path.name)
        if zip_sha1 != zip_sha2:
            raise SystemExit(f"Offline ZIP reproducibility FAILED: {zip_sha1} != {zip_sha2}")
        if pyz_sha1 != pyz_sha2:
            raise SystemExit(f"PYZ reproducibility FAILED: {pyz_sha1} != {pyz_sha2}")

    print(
        json.dumps(
            {
                "reproducible_verified": bool(args.verify),
                "offline_zip": {"path": str(zip_path), "sha256": zip_sha1},
                "pyz_archive": {"path": str(pyz_path), "sha256": pyz_sha1},
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
