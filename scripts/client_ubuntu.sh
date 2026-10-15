#!/usr/bin/env bash
set -e

# XmasTunnel - Ubuntu Client Setup & Launch Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================================="
echo "         XmasTunnel Client Setup & Launcher (Ubuntu)      "
echo "=========================================================="

if ! command -v python3 &>/dev/null; then
    echo "[*] Installing Python3..."
    sudo apt update -qq
    sudo apt install -y -qq python3 python3-pip python3-venv
fi

if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment (.venv)..."
    python3 -m venv .venv
fi

source .venv/bin/activate
pip install -U pip setuptools --quiet
pip install -r requirements.txt --quiet
pip install -e . --quiet

INPUT="${1:-}"

if [[ "$INPUT" =~ ^xmas:// ]]; then
    echo "[*] Starting client with config token..."
    python3 -m xmastunnel client --token "$INPUT"
elif [ -n "$INPUT" ]; then
    SERVER_IP="$INPUT"
    PORT="${2:-8443}"
    KEY="${3:-}"
    EXTRA_ARGS="${@:4}"
    if [ -z "$KEY" ]; then
        read -rp "Enter Pre-Shared Key (PSK): " KEY
    fi
    python3 -m xmastunnel client -s "$SERVER_IP" -p "$PORT" --key "$KEY" $EXTRA_ARGS
else
    # Interactive prompt: accepts either full xmas:// token or manual IP
    read -rp "Enter Client Config Token (xmas://...) or Server IP: " USER_IN
    if [[ "$USER_IN" =~ ^xmas:// ]]; then
        python3 -m xmastunnel client --token "$USER_IN"
    else
        SERVER_IP="${USER_IN:-127.0.0.1}"
        read -rp "Enter Server Port [default: 8443]: " PORT
        PORT="${PORT:-8443}"
        read -rp "Enter Pre-Shared Key (PSK): " KEY
        read -rp "Send Xmas Tree probe packet? (Y/n): " PROBE
        PROBE_FLAG="--xmas-probe"
        if [[ "$PROBE" =~ ^[Nn]$ ]]; then
            PROBE_FLAG=""
        fi
        python3 -m xmastunnel client -s "$SERVER_IP" -p "$PORT" --key "$KEY" $PROBE_FLAG
    fi
fi
