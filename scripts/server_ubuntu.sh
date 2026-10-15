#!/usr/bin/env bash
set -e

# XmasTunnel - Ubuntu Server Setup & Launch Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================================="
echo "         XmasTunnel Server Setup & Launcher (Ubuntu)      "
echo "=========================================================="

# 1. Check Python3 and venv
if ! command -v python3 &>/dev/null; then
    echo "[*] Installing Python3 and tools..."
    sudo apt update -qq
    sudo apt install -y -qq python3 python3-pip python3-venv libcap2-bin curl
fi

# 2. Virtual Environment
if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment (.venv)..."
    python3 -m venv .venv
fi

source .venv/bin/activate
pip install -U pip setuptools --quiet
pip install -r requirements.txt --quiet
pip install -e . --quiet

# 3. Enable CAP_NET_RAW for packet engine without root
PYTHON_BIN="$(readlink -f .venv/bin/python3)"
if command -v setcap &>/dev/null; then
    sudo setcap cap_net_raw,cap_net_admin+eip "$PYTHON_BIN" 2>/dev/null || true
fi

# 4. Parameters
if [ $# -eq 0 ] && [ -t 0 ]; then
    # Interactive wizard: asks Port, Client IP, Flags, gives Token
    python3 -m xmastunnel server --interactive
else
    HOST="${1:-0.0.0.0}"
    PORT="${2:-8443}"
    KEY="${3:-}"
    echo "[*] Starting XmasTunnel Server on $HOST:$PORT..."
    if [ -n "$KEY" ]; then
        python3 -m xmastunnel server --host "$HOST" --port "$PORT" --key "$KEY"
    else
        python3 -m xmastunnel server --host "$HOST" --port "$PORT"
    fi
fi
