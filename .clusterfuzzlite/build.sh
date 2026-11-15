#!/bin/bash -eu
# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT

SITE_PKGS="$(python3 -c 'import site; print(site.getsitepackages()[0])')"
cp -r "$SRC/clearlens/clearlens" "$SITE_PKGS/"
compile_python_fuzzer "$SRC/clearlens/tests/fuzz_clearlens.py"
