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
    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv
fi

if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment (.venv)..."
    python3 -m venv .venv
fi

source .venv/bin/activate
pip install -U pip --quiet
pip install -r requirements.txt --quiet

SERVER_IP="${1:-}"
PORT="${2:-8443}"
KEY="${3:-}"
EXTRA_ARGS="${@:4}"

if [ -z "$SERVER_IP" ]; then
    read -rp "Enter Server IP Address [default: 127.0.0.1]: " SERVER_IP
    SERVER_IP="${SERVER_IP:-127.0.0.1}"
fi

if [ -z "$KEY" ]; then
    read -rp "Enter Pre-Shared Key (PSK): " KEY
fi

read -rp "Enable Xmas Tree probe before connection? (y/N): " XMAS_CHOICE
if [[ "$XMAS_CHOICE" =~ ^[Yy]$ ]]; then
    EXTRA_ARGS="$EXTRA_ARGS --xmas-probe"
fi

echo "[*] Connecting to $SERVER_IP:$PORT..."
python3 -m xmastunnel client -s "$SERVER_IP" -p "$PORT" --key "$KEY" $EXTRA_ARGS
