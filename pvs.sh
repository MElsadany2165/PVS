#!/usr/bin/env bash
# PVS - Personal Vulnerability Scanner & Remediation Engine
# Multi-platform launcher script for Linux and macOS

set -e

# Resolve repository directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$SCRIPT_DIR"

# Locate Python binary (virtualenv preferred)
if [ -f "$SCRIPT_DIR/venv/bin/python" ]; then
    PYTHON="$SCRIPT_DIR/venv/bin/python"
elif [ -f "$SCRIPT_DIR/.venv/bin/python" ]; then
    PYTHON="$SCRIPT_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    BASE_PYTHON="python3"
    # Auto-bootstrap virtual environment to seamlessly handle PEP 668
    if ! "$BASE_PYTHON" -c "import rich, pvs" 2>/dev/null; then
        echo "[*] Setting up isolated environment (.venv) for PEP 668 compliance..."
        "$BASE_PYTHON" -m venv "$SCRIPT_DIR/.venv" 2>/dev/null || true
        if [ -f "$SCRIPT_DIR/.venv/bin/python" ]; then
            "$SCRIPT_DIR/.venv/bin/python" -m pip install -q -e "$SCRIPT_DIR" 2>/dev/null || \
            "$SCRIPT_DIR/.venv/bin/python" -m pip install -q -r "$SCRIPT_DIR/requirements.txt" 2>/dev/null || true
            PYTHON="$SCRIPT_DIR/.venv/bin/python"
        else
            PYTHON="$BASE_PYTHON"
        fi
    else
        PYTHON="$BASE_PYTHON"
    fi
elif command -v python >/dev/null 2>&1; then
    PYTHON="python"
else
    echo "[-] Error: Python 3.10+ is required but not found in PATH." >&2
    echo "    Please install Python 3 (e.g., sudo apt install python3 python3-pip python3-venv)" >&2
    exit 1
fi

# If arguments passed, pass them directly; otherwise launch wizard
if [ $# -eq 0 ]; then
    exec "$PYTHON" -m pvs wizard
else
    exec "$PYTHON" -m pvs "$@"
fi
