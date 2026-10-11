#!/usr/bin/env bash
# PVS - Personal Vulnerability Scanner & Remediation Engine
# Multi-platform launcher and installer script for Linux and macOS

set -e

# Resolve repository directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$SCRIPT_DIR"

# Handle global CLI installation command: ./pvs.sh install
if [ "$1" = "install" ] || [ "$1" = "--install" ]; then
    echo "[*] Installing PVS command globally on Linux/macOS..."
    
    # 1. Resolve Python
    if command -v python3 >/dev/null 2>&1; then
        PY="python3"
    elif command -v python >/dev/null 2>&1; then
        PY="python"
    else
        echo "[-] Error: Python 3.10+ is required but not installed." >&2
        exit 1
    fi

    # 2. Setup virtualenv or user install
    if ! "$PY" -c "import rich, pvs" 2>/dev/null; then
        echo "[*] Bootstrapping PVS dependencies..."
        if "$PY" -m venv "$SCRIPT_DIR/.venv" 2>/dev/null && [ -f "$SCRIPT_DIR/.venv/bin/python" ]; then
            "$SCRIPT_DIR/.venv/bin/python" -m pip install -q -e "$SCRIPT_DIR" 2>/dev/null || \
            "$SCRIPT_DIR/.venv/bin/python" -m pip install -q -r "$SCRIPT_DIR/requirements.txt" 2>/dev/null
        else
            # Try pip install with --break-system-packages for modern PEP 668 systems (Debian 12+, Ubuntu 23+)
            "$PY" -m pip install --user --break-system-packages -q -e "$SCRIPT_DIR" 2>/dev/null || \
            "$PY" -m pip install --user -q -e "$SCRIPT_DIR" 2>/dev/null || true
        fi
    fi

    # 3. Create global symlink in ~/.local/bin
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
    ln -sf "$SCRIPT_DIR/pvs.sh" "$INSTALL_DIR/pvs"
    chmod +x "$SCRIPT_DIR/pvs.sh" "$INSTALL_DIR/pvs" 2>/dev/null || true

    echo "[+] Installation complete!"
    echo "    PVS is linked to: $INSTALL_DIR/pvs"
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        echo "    Tip: Add ~/.local/bin to your PATH in ~/.bashrc or ~/.zshrc if not already present:"
        echo "         export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
    echo "    You can now run 'pvs' from anywhere!"
    exit 0
fi

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
            # Fallback for systems where python3-venv is not pre-installed
            "$BASE_PYTHON" -m pip install --user --break-system-packages -q -e "$SCRIPT_DIR" 2>/dev/null || true
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
