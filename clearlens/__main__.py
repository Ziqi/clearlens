# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""Package module execution entrypoint (`python -m clearlens`)."""

from __future__ import annotations

from clearlens.cli import main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
