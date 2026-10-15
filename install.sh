#!/usr/bin/env bash
set -e

# XmasTunnel - One-Command Automated Installer for Ubuntu / Debian

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}==========================================================${NC}"
echo -e "${CYAN}     XmasTunnel Automated Installer (Ubuntu/Debian)       ${NC}"
echo -e "${CYAN}==========================================================${NC}"

# 1. Root / Sudo check
SUDO=""
if [ "$EUID" -ne 0 ]; then
    if command -v sudo &>/dev/null; then
        SUDO="sudo"
    else
        echo -e "${RED}[!] Error: This script must be run as root or with sudo.${NC}" >&2
        exit 1
    fi
fi

# 2. Update apt and install required system packages
echo -e "${YELLOW}[*] Installing system dependencies (Python3, venv, pip, libcap2-bin, git)...${NC}"
$SUDO apt-get update -y -qq
$SUDO apt-get install -y -qq python3 python3-pip python3-venv libcap2-bin curl git

# 3. Determine target directory and ensure repo code exists
INSTALL_DIR="/opt/xmastunnel"
CURRENT_DIR="$(pwd)"

if [ -f "$CURRENT_DIR/xmastunnel/__init__.py" ]; then
    # Running inside already-cloned local repository
    INSTALL_DIR="$CURRENT_DIR"
    echo -e "${GREEN}[+] Using current directory: $INSTALL_DIR${NC}"
else
    echo -e "${YELLOW}[*] Setting up application in $INSTALL_DIR...${NC}"
    $SUDO mkdir -p "$INSTALL_DIR"
    
    if [ -d "$CURRENT_DIR/xmastunnel" ]; then
        echo -e "${YELLOW}[*] Copying local files into $INSTALL_DIR...${NC}"
        $SUDO cp -r "$CURRENT_DIR"/* "$INSTALL_DIR"/
    elif [ -d "$INSTALL_DIR/xmastunnel" ]; then
        echo -e "${YELLOW}[*] Pulling latest code into $INSTALL_DIR...${NC}"
        git -C "$INSTALL_DIR" pull --quiet || true
    else
        echo -e "${YELLOW}[*] Cloning repository into $INSTALL_DIR...${NC}"
        # Remove any partial empty directory before clone if needed
        $SUDO rm -rf "$INSTALL_DIR"
        $SUDO git clone https://github.com/thehornet2002/XmasTunnel.git "$INSTALL_DIR"
    fi
fi

cd "$INSTALL_DIR"

# 4. Create isolated Python Virtual Environment
VENV_DIR="$INSTALL_DIR/.venv"
echo -e "${YELLOW}[*] Creating Python Virtual Environment ($VENV_DIR)...${NC}"
python3 -m venv "$VENV_DIR"

# 5. Install dependencies and xmastunnel package in venv
echo -e "${YELLOW}[*] Installing Python dependencies and xmastunnel package...${NC}"
"$VENV_DIR/bin/pip" install --upgrade pip setuptools --quiet
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
    "$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt" --quiet
else
    "$VENV_DIR/bin/pip" install "cryptography>=42.0.0" "pytest>=8.0.0" --quiet
fi

# Install xmastunnel package into site-packages so it's always importable
"$VENV_DIR/bin/pip" install -e "$INSTALL_DIR" --quiet

# 6. Set Linux capabilities for Raw Packet Engine (CAP_NET_RAW)
VENV_PYTHON="$(readlink -f "$VENV_DIR/bin/python3")"
echo -e "${YELLOW}[*] Assigning CAP_NET_RAW and CAP_NET_ADMIN capabilities to venv Python...${NC}"
$SUDO setcap cap_net_raw,cap_net_admin+eip "$VENV_PYTHON" 2>/dev/null || {
    echo -e "${YELLOW}[!] Warning: Could not set capabilities directly. Raw sockets will require sudo.${NC}"
}

# 7. Create global CLI wrappers in /usr/local/bin
echo -e "${YELLOW}[*] Installing global command line wrappers (/usr/local/bin/xmastunnel)...${NC}"

$SUDO tee /usr/local/bin/xmastunnel >/dev/null <<EOF
#!/usr/bin/env bash
export PYTHONPATH="$INSTALL_DIR:\$PYTHONPATH"
exec "$VENV_DIR/bin/python3" -m xmastunnel "\$@"
EOF
$SUDO chmod +x /usr/local/bin/xmastunnel

$SUDO tee /usr/local/bin/xmastunnel-server >/dev/null <<EOF
#!/usr/bin/env bash
export PYTHONPATH="$INSTALL_DIR:\$PYTHONPATH"
PORT="\${1:-8443}"
KEY="\${2:-}"
if [ -n "\$KEY" ]; then
    exec "$VENV_DIR/bin/python3" -m xmastunnel server -p "\$PORT" --key "\$KEY"
else
    exec "$VENV_DIR/bin/python3" -m xmastunnel server -p "\$PORT"
fi
EOF
$SUDO chmod +x /usr/local/bin/xmastunnel-server

$SUDO tee /usr/local/bin/xmastunnel-client >/dev/null <<EOF
#!/usr/bin/env bash
export PYTHONPATH="$INSTALL_DIR:\$PYTHONPATH"
SERVER="\${1:-127.0.0.1}"
PORT="\${2:-8443}"
KEY="\${3:-}"
EXTRA="\${@:4}"
if [ -z "\$KEY" ]; then
    echo -e "${RED}[!] Usage: xmastunnel-client <SERVER_IP> <PORT> <KEY> [OPTIONS]${NC}"
    exit 1
fi
exec "$VENV_DIR/bin/python3" -m xmastunnel client -s "\$SERVER" -p "\$PORT" --key "\$KEY" \$EXTRA
EOF
$SUDO chmod +x /usr/local/bin/xmastunnel-client

# 8. Create systemd service template for server
SERVICE_PATH="/etc/systemd/system/xmastunnel.service"
echo -e "${YELLOW}[*] Creating systemd service ($SERVICE_PATH)...${NC}"

$SUDO tee "$SERVICE_PATH" >/dev/null <<EOF
[Unit]
Description=XmasTunnel AES-256-GCM Secure TCP Tunnel Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment=PYTHONPATH=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/python3 -m xmastunnel server --host 0.0.0.0 --port 8443
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

$SUDO systemctl daemon-reload 2>/dev/null || true

echo -e "${GREEN}==========================================================${NC}"
echo -e "${GREEN}       XmasTunnel Installation Completed Successfully!    ${NC}"
echo -e "${GREEN}==========================================================${NC}"
echo -e "Installation Directory: ${CYAN}$INSTALL_DIR${NC}"
echo -e "Virtual Environment:    ${CYAN}$VENV_DIR${NC}"
echo -e "Global commands available:"
echo -e "  - ${CYAN}xmastunnel --help${NC}                   (Full CLI options)"
echo -e "  - ${CYAN}xmastunnel gen-key${NC}                  (Generate random 256-bit PSK)"
echo -e "  - ${CYAN}xmastunnel-server [PORT] [KEY]${NC}      (Start server quickly)"
echo -e "  - ${CYAN}xmastunnel-client <IP> <PORT> <KEY>${NC} (Connect client quickly)"
echo -e "  - ${CYAN}xmastunnel test-flags --matrix${NC}      (Run TCP flag & Xmas tests)"
echo -e ""
echo -e "To start server as background systemd service:"
echo -e "  ${YELLOW}sudo systemctl restart xmastunnel${NC}"
echo -e "  ${YELLOW}sudo systemctl enable xmastunnel${NC}"
echo -e "  ${YELLOW}sudo journalctl -u xmastunnel -f${NC}"
echo -e "${GREEN}==========================================================${NC}"
