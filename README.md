# XmasTunnel 🎄
### High-Performance AES-256-GCM Encrypted TCP Tunnel with SOCKS5 Proxy & Low-Level TCP Flag Inspection

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-22%20Passed-brightgreen.svg)]()

---

## 1. Project Overview

**XmasTunnel** is a production-grade, modular client-server TCP tunneling solution designed for encrypted communication, connection multiplexing via a local SOCKS5 proxy, and low-level TCP packet inspection (`FIN, SYN, RST, PSH, ACK, URG, ECE, CWR`).

The software features complete architectural separation between:
- **Authenticated Encryption Layer:** AES-256-GCM with 128-bit authentication tags, directional session keys, monotonic nonces, and sliding-window anti-replay defense.
- **Multiplexed SOCKS5 Proxy:** Built-in RFC 1928 SOCKS5 server listening locally (default `127.0.0.1:10829`) and proxying applications/browsers through the encrypted tunnel.
- **Packet Engine (Low-Level Control):** Real-time crafting, validation, and injection of raw IPv4/TCP headers with custom TCP control flags (such as the classic Christmas tree scan `FIN|PSH|URG`, `ALL_FLAGS`, or custom bitmasks) utilizing **Npcap** on Windows and **Raw Sockets** (`AF_PACKET` / `IPPROTO_RAW`) on Linux.

---

## 2. Architecture & Modules

```
XmasTunnel/
├── xmastunnel/
│   ├── crypto/                 # Cryptography & Key Management
│   │   ├── aes_gcm.py          # AES-256-GCM cipher with AAD validation
│   │   ├── kdf.py              # HKDF-SHA256 & PBKDF2 key derivation
│   │   └── nonce_manager.py    # Monotonic 96-bit nonces & anti-replay window
│   ├── protocol/               # Protocol & Framing Layer
│   │   ├── frame.py            # 24-byte binary framing & stream parser
│   │   └── state_machine.py    # Independent protocol state machine
│   ├── transport/              # Network Transport Engines
│   │   ├── tcp_transport.py    # Standard non-blocking TCP socket stream
│   │   └── raw_transport.py    # Raw packet tunnel (Npcap / AF_PACKET)
│   ├── session/                # Session Lifecycle Management
│   │   ├── session.py          # 4-way cryptographic handshake & re-keying
│   │   └── session_manager.py  # Concurrency limits & idle session reaper
│   ├── socks/                  # SOCKS5 Proxy & Multiplexing
│   │   └── socks_server.py     # RFC 1928 local proxy & stream multiplexer
│   ├── packet_engine/          # Low-Level Packet Crafting
│   │   ├── flags.py            # TCP control flags bitmasks & test profiles
│   │   ├── checksum.py         # RFC 1071 internet checksum & pseudo-header
│   │   ├── packet.py           # IPv4 & TCP binary header serialization
│   │   └── raw_engine.py       # Raw packet builder & capability probe
│   ├── config/                 # Configuration & Logging
│   │   ├── config.py           # Server/Client dataclasses & xmas:// tokens
│   │   └── logger.py           # Sanitized logging redacting sensitive keys
│   ├── server.py               # Tunnel Server Implementation
│   ├── client.py               # Tunnel Client Implementation
│   └── cli.py                  # Command Line Interface (CLI)
├── tests/                      # Comprehensive Test Suite (22 Tests)
│   ├── test_crypto.py
│   ├── test_protocol.py
│   ├── test_session.py
│   ├── test_transport.py
│   ├── test_packet_engine.py
│   ├── test_socks.py
│   └── test_integration.py
├── docs/                       # Technical Documentation
│   ├── ARCHITECTURE.md
│   ├── PROTOCOL.md
│   ├── LOW_LEVEL_NETWORKING.md
│   └── SECURITY.md
├── scripts/                    # Platform Setup & Launch Scripts
│   ├── install_ubuntu.sh       # Ubuntu one-command installer
│   ├── server_ubuntu.sh        # Ubuntu server launch wizard
│   ├── client_ubuntu.sh        # Ubuntu client launch wizard
│   ├── server_windows.ps1      # Windows server launch wizard (PowerShell)
│   ├── client_windows.ps1      # Windows client launch wizard (PowerShell)
│   ├── server_windows.bat      # Windows server quick double-click launcher
│   └── client_windows.bat      # Windows client quick double-click launcher
├── install.sh                  # Root automated installer for Linux
├── pyproject.toml              # Standard Python build configuration
├── setup.py                    # Setuptools installer
└── requirements.txt            # Package dependencies
```

---

## 3. Quick Installation

### Linux / Ubuntu (One-Command Automated Installer)

Run the following command on your server or client:

```bash
sudo bash install.sh
```

Or directly via `curl`:
```bash
curl -fsSL https://raw.githubusercontent.com/thehornet2002/XmasTunnel/main/install.sh | sudo bash
```

This installer automatically:
- Installs system prerequisites (`python3-venv`, `pip`, `libcap2-bin`, `git`, `curl`).
- Builds an isolated virtual environment (`.venv`).
- Installs dependencies (`cryptography`, `scapy`, `pytest`) and packages `xmastunnel`.
- Assigns `CAP_NET_RAW` Linux capabilities for packet crafting without root.
- Adds global terminal binaries (`xmastunnel`, `xmastunnel-server`, `xmastunnel-client`).
- Configures a `systemd` background service template at `/etc/systemd/system/xmastunnel.service`.

### Windows Installation

1. Clone or download the repository to your machine.
2. Ensure [Python 3.9+](https://python.org) is installed and in your system PATH.
3. Install dependencies:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   pip install -e .
   ```
4. Ensure [Wireshark](https://www.wireshark.org/) or [Npcap](https://npcap.com/) is installed if you intend to inspect or inject raw packets.

---

## 4. Usage Guide

### Step 1: Launch the Server (Ubuntu or Windows)

Run the interactive server setup wizard:

```bash
# On Ubuntu:
xmastunnel-server

# Or on Windows:
powershell -ExecutionPolicy Bypass -File .\scripts\server_windows.ps1
```

The interactive wizard prompts for:
1. **Listening Port:** e.g. `1258` (or default `8443`).
2. **Allowed Client IP:** Press Enter for `ANY`.
3. **TCP Flags Configuration (Two-Part):**
   - **Part A (Server TX Flags):** Flags emitted by server (e.g. `SYN|ACK`, `RST|ACK`, or custom).
   - **Part B (Client TX Flags):** Flags expected from client (e.g. `XMAS_TREE` = `FIN|PSH|URG`).
4. **Transmission Engine:**
   - `[1] Raw Xmas Packet Tunnel:` Bypasses OS kernel stack; every packet on the wire has your exact custom flags.
   - `[2] Standard TCP Stream:` Uses reliable TCP socket stream, compatible with all routers and NATs.

The server generates a self-contained, portable client token:
```text
========================================================================
                   CLIENT CONFIGURATION PACKAGE                   
========================================================================
 Server IP:        31.57.46.120
 Port:             1258
 Shared Key (PSK): 40f78835a1073540dffec5af6006ebad8453f005deefea2b...
 Engine Mode:      Standard TCP
 Server TX Flags:  SYN_ACK
 Client TX Flags:  XMAS_TREE
 Allowed Clt IP:   ANY
------------------------------------------------------------------------
 >>> CLIENT CONFIG TOKEN:

xmas://eyJzZXJ2ZXIiOiIzMS41Ny40Ni4xMjAiLCJwb3J0IjoxMjU4LCJwc2siOiI0MGY3ODgzNW...

 >>> ONE-COMMAND LAUNCH FOR CLIENT:
 xmastunnel client --token "xmas://..."
========================================================================
```

---

### Step 2: Connect the Client & Start SOCKS5 Proxy

On your client machine (Windows or Linux), launch the client using the generated token:

#### On Windows (PowerShell):
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\client_windows.ps1 -Token "xmas://<TOKEN>"
```

#### On Linux / Ubuntu:
```bash
xmastunnel-client "xmas://<TOKEN>"
```

#### Direct Python Execution:
```bash
python -m xmastunnel client --token "xmas://<TOKEN>"
```

Upon connection, the client establishes the encrypted tunnel and activates the local SOCKS5 proxy:
```text
[+] SOCKS5 PROXY ACTIVE ON: 127.0.0.1:10829
[+] All client traffic is multiplexed & encrypted via AES-256-GCM
[+] Configure browser / Telegram / apps to SOCKS5 127.0.0.1:10829
[*] Tunnel active. Press Ctrl+C to stop.
```

---

## 5. Using the SOCKS5 Proxy

Once the client is running, configure your browser, operating system, or application to route traffic through the tunnel:

- **Proxy Protocol:** `SOCKS5`
- **Host / IP:** `127.0.0.1`
- **Port:** `10829`

### Terminal Testing:
Verify external routing using `curl`:
```bash
curl -x socks5h://127.0.0.1:10829 https://api.ipify.org
```
*(The returned IP address will be your remote tunnel server's public IP).*

---

## 6. TCP Flag Inspection & Packet Engine

XmasTunnel includes an independent raw packet analysis engine to inspect and craft arbitrary TCP control flag combinations:

```bash
# Run a full matrix test across all standard & anomalous profiles
python -m xmastunnel test-flags --matrix

# Test a custom flag combination (e.g. FIN, URG, PSH - Xmas Tree scan)
python -m xmastunnel test-flags --flags "FIN,URG,PSH" --dst-ip 127.0.0.1 --dst-port 8443
```

### Supported Flag Profiles:
- **`XMAS_TREE` (`FIN|PSH|URG`):** The classic Christmas tree packet with push, urgent, and fin flags enabled.
- **`SYN_PROBE` (`SYN`):** Standard connection initiation probe.
- **`SYN_ACK` (`SYN|ACK`):** Server connection confirmation response.
- **`NULL_FLAGS` (`NONE`):** Zero flags set; tests stack behavior against undefined states.
- **`ALL_FLAGS` (`FIN|SYN|RST|PSH|ACK|URG|ECE|CWR`):** Maximum stress probe testing firewall rule sets.

---

## 7. Verification & Test Suite

The project includes 22 unit, cryptographic, protocol, and end-to-end integration tests:

```bash
pytest tests -v
```

```text
tests/test_crypto.py::test_aes_gcm_encrypt_decrypt_roundtrip PASSED      [  4%]
tests/test_crypto.py::test_aes_gcm_tamper_detection PASSED               [  9%]
tests/test_crypto.py::test_psk_generation_and_detection PASSED           [ 13%]
tests/test_crypto.py::test_kdf_derivation_deterministic PASSED           [ 18%]
tests/test_crypto.py::test_nonce_manager_monotonic PASSED                [ 22%]
tests/test_crypto.py::test_replay_protection_window PASSED               [ 27%]
tests/test_integration.py::test_full_tunnel_integration_and_rekey PASSED [ 31%]
tests/test_integration.py::test_client_wrong_psk_rejected PASSED         [ 36%]
tests/test_packet_engine.py::test_flag_parsing_and_str PASSED            [ 40%]
tests/test_packet_engine.py::test_checksum_algorithm PASSED              [ 45%]
tests/test_packet_engine.py::test_raw_tcp_packet_craft_and_parse PASSED  [ 50%]
tests/test_packet_engine.py::test_flag_matrix_execution PASSED           [ 54%]
tests/test_protocol.py::test_frame_pack_unpack_roundtrip PASSED          [ 59%]
tests/test_protocol.py::test_frame_parser_fragmentation PASSED           [ 63%]
tests/test_protocol.py::test_frame_parser_multiple_frames_in_buffer PASSED [ 68%]
tests/test_protocol.py::test_protocol_state_machine_valid_and_invalid PASSED [ 72%]
tests/test_session.py::test_handshake_flow_success PASSED                [ 77%]
tests/test_session.py::test_handshake_bad_psk_failure PASSED             [ 81%]
tests/test_session.py::test_session_data_encryption_and_anti_replay PASSED [ 86%]
tests/test_session.py::test_session_manager PASSED                       [ 90%]
tests/test_socks.py::test_socks5_proxy_over_xmastunnel PASSED            [ 95%]
tests/test_transport.py::test_tcp_transport_streaming PASSED             [100%]

============================= 22 passed in 1.25s ==============================
```

---

## 8. Security & Cryptographic Standards

- **Cipher:** AES-256 in Galois/Counter Mode (GCM) with 128-bit authentication tags.
- **Key Derivation:** HKDF-SHA256 for high-entropy keys, PBKDF2-HMAC-SHA256 (300,000 iterations) for passphrases.
- **Replay Protection:** 64-frame sliding window matching RFC 6479.
- **Nonce Integrity:** Directional salt (4 bytes) concatenated with a monotonic 64-bit integer counter. Nonce values never repeat within a session key lifespan.
- **Zero Log Leakage:** Built-in regex filters redact keys, passphrases, and tokens from all log output.
