#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""Deterministic ISO/IEC 5962:2021 (SPDX-2.3) JSON SBOM generator for ClearLens."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CREATED_UTC = "2026-11-15T00:00:00Z"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_spdx_document(
    *,
    version: str,
    offline_zip_sha256: str,
    pyz_sha256: str,
) -> dict[str, object]:
    release_base = f"https://github.com/Ziqi/clearlens/releases/download/v{version}"
    supplier = "Person: Ziqi Xiao (2196305+Ziqi@users.noreply.github.com)"
    copyright_text = "Copyright (c) 2026 Ziqi Xiao"

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"clearlens-{version}",
        "documentNamespace": f"https://ziqi.github.io/clearlens/spdx/clearlens-{version}",
        "creationInfo": {
            "created": CREATED_UTC,
            "creators": [
                supplier,
                "Tool: clearlens-spdx-generator-1.0",
            ],
            "licenseListVersion": "3.25",
            "comment": (
                f"Deterministic SPDX 2.3 SBOM for ClearLens v{version} "
                "(zero external runtime dependencies: vanilla HTML/JS + Python >=3.10 stdlib)."
            ),
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-ClearLens-Offline-Web",
                "name": "clearlens-offline-web",
                "versionInfo": version,
                "packageFileName": f"clearlens-offline-v{version}.zip",
                "supplier": supplier,
                "originator": supplier,
                "downloadLocation": f"{release_base}/clearlens-offline-v{version}.zip",
                "filesAnalyzed": False,
                "homepage": "https://ziqi.github.io/clearlens/",
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
                "copyrightText": copyright_text,
                "primaryPackagePurpose": "APPLICATION",
                "summary": (
                    "Zero-backend browser-RAM workbench for BEC wire-fraud triage, "
                    "defensive outbound DLP, and multi-currency exposure de-duplication."
                ),
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": offline_zip_sha256,
                    }
                ],
            },
            {
                "SPDXID": "SPDXRef-Package-ClearLens-CLI",
                "name": "clearlens",
                "versionInfo": version,
                "packageFileName": "clearlens.pyz",
                "supplier": supplier,
                "originator": supplier,
                "downloadLocation": f"{release_base}/clearlens.pyz",
                "filesAnalyzed": False,
                "homepage": "https://github.com/Ziqi/clearlens",
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
                "copyrightText": copyright_text,
                "primaryPackagePurpose": "APPLICATION",
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": pyz_sha256,
                    }
                ],
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:github/Ziqi/clearlens@v{version}",
                    }
                ],
            },
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package-ClearLens-Offline-Web",
            },
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package-ClearLens-CLI",
            },
        ],
    }


def validate_spdx_document(doc: dict[str, object]) -> None:
    required = {"spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace", "creationInfo", "packages"}
    missing = required - set(doc.keys())
    if missing:
        raise SystemExit(f"SPDX validation failed: missing keys {sorted(missing)}")
    if doc.get("spdxVersion") != "SPDX-2.3" or doc.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise SystemExit("Invalid SPDX-2.3 document header")


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate deterministic SPDX 2.3 JSON SBOM for ClearLens")
    ap.add_argument("--version", type=str, default="1.0.0")
    ap.add_argument("--offline-zip", type=Path, required=True)
    ap.add_argument("--pyz", type=Path, required=True)
    ap.add_argument("--output", type=Path, default=REPO_ROOT / "dist" / "clearlens-1.0.0.spdx.json")
    ap.add_argument("--verify", action="store_true")
    args = ap.parse_args()

    doc = build_spdx_document(
        version=args.version,
        offline_zip_sha256=_sha256_file(args.offline_zip),
        pyz_sha256=_sha256_file(args.pyz),
    )
    validate_spdx_document(doc)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(doc, indent=2, sort_keys=False) + "\n"
    args.output.write_text(payload, encoding="utf-8")
    if args.verify:
        reloaded = json.loads(args.output.read_text(encoding="utf-8"))
        validate_spdx_document(reloaded)
    print(f"SPDX_SBOM_OK path={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
