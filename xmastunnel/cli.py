import argparse
import json
import sys
import time
from .config.config import (
    ServerConfig,
    ClientConfig,
    load_server_config,
    load_client_config,
    encode_client_token,
    decode_client_token,
)
from .config.logger import setup_logger
from .crypto.kdf import generate_server_psk
from .packet_engine.flags import TEST_PROFILES, parse_flags, flags_to_str
from .packet_engine.raw_engine import RawPacketEngine, CapabilityReport
from .server import TunnelServer
from .client import TunnelClient


def get_public_ip() -> str:
    """Discovers external public IP address with fallbacks."""
    import urllib.request
    providers = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
    ]
    for url in providers:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/7.68.0"})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                ip = resp.read().decode("utf-8").strip()
                if ip:
                    return ip
        except Exception:
            continue
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def cmd_gen_key(args: argparse.Namespace) -> None:
    psk = generate_server_psk()
    print("=" * 64)
    print("NEW RANDOM 256-BIT PRE-SHARED KEY (HEX):")
    print(psk)
    print("=" * 64)


def cmd_server(args: argparse.Namespace) -> None:
    if getattr(args, "interactive", False) or (not args.config and args.port == 8443 and not args.key and sys.stdin.isatty()):
        # Interactive Setup Wizard
        print("=" * 68)
        print("          XmasTunnel Server Setup & Config Generator          ")
        print("=" * 68)
        # 1. Port
        p_in = input("1. Enter listening port [default: 8443]: ").strip()
        port = int(p_in) if p_in else 8443

        # 2. Client IP
        client_ip = input("2. Enter allowed Client IP (press Enter for ANY): ").strip() or "ANY"

        # 3. Two-Part Flags Configuration
        print("\n3. Configure TCP Flags in Two Parts:")
        print("   --- [Part A: Server TX Flags (Emitted by Server)] ---")
        print("   [1] SYN|ACK (Normal Handshake Response - Default)")
        print("   [2] RST|ACK (Connection Reset/Probe Response)")
        print("   [3] Xmas Tree (FIN|PSH|URG)")
        print("   [4] Custom flags (e.g. ACK,PSH)")
        print("   [5] None")
        sf_choice = input("Select Server TX profile [1-5, default: 1]: ").strip()
        if sf_choice == "2":
            server_flags = "RST_ACK"
        elif sf_choice == "3":
            server_flags = "XMAS_TREE"
        elif sf_choice == "4":
            server_flags = input("Enter server flags: ").strip() or "SYN_ACK"
        elif sf_choice == "5":
            server_flags = "NONE"
        else:
            server_flags = "SYN_ACK"

        print("\n   --- [Part B: Client TX Flags (Emitted by Client)] ---")
        print("   [1] Xmas Tree (FIN|PSH|URG) - Classic Christmas Scan (Default)")
        print("   [2] SYN Probe (SYN)")
        print("   [3] All Flags (FIN|SYN|RST|PSH|ACK|URG|ECE|CWR)")
        print("   [4] Custom flags (e.g. FIN,ACK)")
        print("   [5] None")
        cf_choice = input("Select Client TX profile [1-5, default: 1]: ").strip()
        if cf_choice == "2":
            client_flags = "SYN"
        elif cf_choice == "3":
            client_flags = "ALL_FLAGS"
        elif cf_choice == "4":
            client_flags = input("Enter client flags: ").strip() or "XMAS_TREE"
        elif cf_choice == "5":
            client_flags = "NONE"
        else:
            client_flags = "XMAS_TREE"

        # 4. Transmission Mode
        print("\n4. Select Transmission Engine:")
        print("   [1] Standard TCP Stream with AES-256-GCM (Compatible with all routers, NAT, and ISPs) [Default]")
        print("   [2] Raw Packet Tunnel (Direct L3/L4 injection - requires public IP without NAT router)")
        m_choice = input("Select Engine [1-2, default: 1]: ").strip()
        raw_mode = True if m_choice == "2" else False

        # 5. Key
        psk = args.key or generate_server_psk()

        # 6. Public IP
        print("\n[*] Detecting Server Public IP...")
        server_ip = get_public_ip()
        ip_override = input(f"Detected IP: {server_ip}. Press Enter to keep or type IP: ").strip()
        if ip_override:
            server_ip = ip_override

        # 7. Generate configuration token
        token = encode_client_token(
            server_ip=server_ip,
            port=port,
            psk=psk,
            client_flags=client_flags,
            server_flags=server_flags,
            client_ip=client_ip,
            raw_mode=raw_mode,
        )

        print("\n" + "=" * 72)
        print("                   CLIENT CONFIGURATION PACKAGE                   ")
        print("=" * 72)
        print(f" Server IP:        {server_ip}")
        print(f" Port:             {port}")
        print(f" Shared Key (PSK): {psk}")
        print(f" Engine Mode:      {'Raw Packet Tunnel (Custom Flags in Wireshark)' if raw_mode else 'Standard TCP'}")
        print(f" Server TX Flags:  {server_flags}")
        print(f" Client TX Flags:  {client_flags}")
        print(f" Allowed Clt IP:   {client_ip}")
        print("-" * 72)
        print(" >>> CLIENT CONFIG TOKEN (Copy & paste into Client):")
        print(f"\n{token}\n")
        print(" >>> ONE-COMMAND LAUNCH FOR CLIENT:")
        print(f' xmastunnel client --token "{token}"')
        print("=" * 72 + "\n")

        with open("client_token.txt", "w", encoding="utf-8") as f:
            f.write(token + "\n")
        print("[+] Token saved to 'client_token.txt'. Starting server...\n")

        config = ServerConfig(
            host=args.host,
            port=port,
            psk=psk,
            server_flags=server_flags,
            client_flags=client_flags,
            raw_mode=raw_mode,
            rate_limit_bytes_per_sec=args.rate_limit,
            verbose=args.verbose,
        )
    elif args.config:
        config = load_server_config(args.config)
        if getattr(args, "raw", False):
            config.raw_mode = True
    else:
        config = ServerConfig(
            host=args.host,
            port=args.port,
            psk=args.key,
            raw_mode=getattr(args, "raw", False),
            rate_limit_bytes_per_sec=args.rate_limit,
            verbose=args.verbose,
        )

    server = TunnelServer(config)
    print(f"[*] Starting XmasTunnel Server on {config.host}:{config.port}...")
    server.start(blocking=True)


def cmd_client(args: argparse.Namespace) -> None:
    remote_host = args.server
    remote_port = args.port
    psk = args.key
    client_flags = "NONE"
    server_flags = "NONE"
    raw_mode = getattr(args, "raw", False)

    # 1. Token passed via argument
    if getattr(args, "token", None):
        cfg_data = decode_client_token(args.token)
        remote_host = cfg_data.get("server", remote_host)
        remote_port = int(cfg_data.get("port", remote_port))
        psk = cfg_data.get("psk", psk)
        client_flags = cfg_data.get("client_flags", cfg_data.get("flags", "NONE"))
        server_flags = cfg_data.get("server_flags", "NONE")
        if "raw" in cfg_data:
            raw_mode = cfg_data["raw"]

    # 2. Interactive token prompt if key not given
    elif not psk and not args.config and sys.stdin.isatty():
        print("=" * 64)
        print("          XmasTunnel Client Launcher                      ")
        print("=" * 64)
        token_input = input("Paste Client Configuration Token (xmas://...): ").strip()
        if token_input.startswith("xmas://") or len(token_input) > 20:
            cfg_data = decode_client_token(token_input)
            remote_host = cfg_data.get("server", remote_host)
            remote_port = int(cfg_data.get("port", remote_port))
            psk = cfg_data.get("psk", "")
            client_flags = cfg_data.get("client_flags", cfg_data.get("flags", "NONE"))
            server_flags = cfg_data.get("server_flags", "NONE")
            if "raw" in cfg_data:
                raw_mode = cfg_data["raw"]
        else:
            psk = token_input

    if args.config:
        config = load_client_config(args.config)
        if raw_mode:
            config.raw_mode = True
    else:
        if not psk:
            print("[!] Error: Pre-shared key or --token is required.", file=sys.stderr)
            sys.exit(1)
        config = ClientConfig(
            remote_host=remote_host,
            remote_port=remote_port,
            psk=psk,
            client_flags=client_flags,
            server_flags=server_flags,
            raw_mode=raw_mode,
            rate_limit_bytes_per_sec=args.rate_limit,
            verbose=args.verbose,
        )

    # 3. Test flags if specified or --xmas-probe
    effective_client_flags = "XMAS_TREE" if getattr(args, "xmas_probe", False) else client_flags
    if effective_client_flags and effective_client_flags != "NONE":
        try:
            parsed_c_flags = parse_flags(effective_client_flags)
            print(f"[*] Dispatching Client TCP Flag Probe [{flags_to_str(parsed_c_flags)}] to {config.remote_host}:{config.remote_port}...")
            engine = RawPacketEngine(fallback_to_loopback=True)
            probe_pkt = engine.craft_tcp_packet(
                src_ip="127.0.0.1",
                dst_ip=config.remote_host,
                src_port=54321,
                dst_port=config.remote_port,
                flags=parsed_c_flags,
                payload=b"CLIENT_TCP_PROBE",
            )
            probe_res = engine.send_packet(probe_pkt, simulate=True)
            print(f"[+] Client Probe Status: {probe_res['status']} | Checksum Valid: {probe_res['checksum_valid']}")
            if server_flags and server_flags != "NONE":
                parsed_s_flags = parse_flags(server_flags)
                print(f"[+] Server Flag Response Profile: [{flags_to_str(parsed_s_flags)}]")
        except Exception as e:
            print(f"[!] Warning during flag test: {e}")

    client = TunnelClient(config)
    try:
        client.connect()
        if args.ping:
            print("[*] Running ping latency checks...")
            for i in range(args.ping):
                rtt = client.ping()
                print(f"[*] Ping #{i+1}: RTT = {rtt:.2f} ms")
                time.sleep(0.5)

        elif args.send:
            payload = args.send.encode("utf-8")
            print(f"[*] Sending: {args.send}")
            client.send_data(payload)
            response = client.recv_data(timeout=5.0)
            if response:
                print(f"[+] Received: {response.decode('utf-8', errors='replace')}")
            else:
                print("[-] No response received.")

        else:
            socks_port = args.socks if args.socks is not None else 10829
            client.start_socks_proxy(listen_host=args.socks_host, listen_port=socks_port)
            print("\n" + "=" * 68)
            print(f" [+] SOCKS5 PROXY ACTIVE ON: {args.socks_host}:{socks_port}")
            print(f" [+] All client traffic is multiplexed & encrypted via AES-256-GCM")
            print(f" [+] Configure browser / Telegram / apps to SOCKS5 {args.socks_host}:{socks_port}")
            print("=" * 68)
            print("[*] Tunnel active. Press Ctrl+C to stop.\n")
            while client.is_connected:
                time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
    finally:
        client.close()


def cmd_test_flags(args: argparse.Namespace) -> None:
    print("=" * 70)
    print("   XmasTunnel Low-Level Network Packet Engine - Flag Testing   ")
    print("=" * 70)

    engine = RawPacketEngine(fallback_to_loopback=True)
    cap = engine.capability.to_dict()
    print(f"OS Platform: {cap['os_name']} {cap['os_release']}")
    print(f"Raw Socket Capability: {'YES' if cap['can_create_raw'] else 'NO (Restricted by OS/Privileges)'}")
    print(f"Note: {cap['detail']}")
    print("-" * 70)

    if args.matrix:
        print("[*] Executing TCP Flag Matrix Test across all standard & anomalous profiles...")
        results = engine.run_flag_matrix_test(
            src_ip=args.src_ip,
            dst_ip=args.dst_ip,
            src_port=args.src_port,
            dst_port=args.dst_port,
        )

        format_str = "{:<18} | {:<25} | {:<9} | {:<10} | {:<12}"
        print(format_str.format("Profile", "Active Flags", "Checksum", "Roundtrip", "Status"))
        print("-" * 85)
        for r in results:
            chk = "VALID" if r["checksum_valid"] else "INVALID"
            rt = "MATCH" if (r["roundtrip_flags_match"] and r["roundtrip_payload_match"]) else "FAIL"
            print(format_str.format(
                r["profile"],
                r["flags_set"][:25],
                chk,
                rt,
                r["send_status"][:12],
            ))
        print("=" * 85)
        if args.json:
            print(json.dumps(results, indent=2))
    else:
        flags = parse_flags(args.flags)
        print(f"[*] Crafting custom TCP packet with flags: {flags_to_str(flags)} (0x{int(flags):02X})")
        packet = engine.craft_tcp_packet(
            src_ip=args.src_ip,
            dst_ip=args.dst_ip,
            src_port=args.src_port,
            dst_port=args.dst_port,
            flags=flags,
            payload=b"XmasTunnel-Custom-Probe",
        )
        status = engine.send_packet(packet, simulate=args.simulate)
        print(f"[+] Packet summary: {packet}")
        print(f"[+] TCP Checksum Valid: {packet.verify_tcp_checksum()} (0x{packet.tcp_header.checksum:04X})")
        print(f"[+] Transmission Status: {status['status']} (Mode: {status['mode']})")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="xmastunnel",
        description="XmasTunnel: AES-256-GCM Encrypted TCP Tunnel with Low-Level Packet & Flag Inspection",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # gen-key command
    p_gen = subparsers.add_parser("gen-key", help="Generate a random 256-bit pre-shared key")
    p_gen.set_defaults(func=cmd_gen_key)

    # server command
    p_srv = subparsers.add_parser("server", help="Start the tunnel server")
    p_srv.add_argument("-i", "--interactive", action="store_true", help="Launch interactive setup wizard and generate client token")
    p_srv.add_argument("--host", default="0.0.0.0", help="Listen host (default: 0.0.0.0)")
    p_srv.add_argument("-p", "--port", type=int, default=8443, help="Listen port (default: 8443)")
    p_srv.add_argument("--key", default=None, help="Pre-shared key (generated automatically if omitted)")
    p_srv.add_argument("--rate-limit", type=int, default=0, help="Rate limit bytes/sec (0 = unlimited)")
    p_srv.add_argument("--raw", action="store_true", help="Run in Raw Packet Tunnel mode (bypasses OS TCP stack)")
    p_srv.add_argument("-c", "--config", help="Path to server JSON config file")
    p_srv.add_argument("-v", "--verbose", action="store_true", help="Verbose debug logging")
    p_srv.set_defaults(func=cmd_server)

    # client command
    p_cli = subparsers.add_parser("client", help="Start the tunnel client")
    p_cli.add_argument("-t", "--token", help="Client configuration token (xmas://...) containing IP, port, key and flags")
    p_cli.add_argument("--socks", type=int, nargs="?", const=10829, default=None, metavar="PORT", help="Run local SOCKS5 proxy server (default port: 10829)")
    p_cli.add_argument("--socks-host", default="127.0.0.1", help="SOCKS5 listen host (default: 127.0.0.1)")
    p_cli.add_argument("-s", "--server", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    p_cli.add_argument("-p", "--port", type=int, default=8443, help="Server port (default: 8443)")
    p_cli.add_argument("--key", default="", help="Pre-shared key")
    p_cli.add_argument("--send", help="Send a single message and print response")
    p_cli.add_argument("--ping", type=int, metavar="COUNT", help="Send N ping frames and report RTT")
    p_cli.add_argument("--xmas-probe", action="store_true", help="Send Xmas Tree probe packet (FIN|PSH|URG) before connecting")
    p_cli.add_argument("--rate-limit", type=int, default=0, help="Rate limit bytes/sec (0 = unlimited)")
    p_cli.add_argument("--raw", action="store_true", help="Run in Raw Packet Tunnel mode (bypasses OS TCP stack)")
    p_cli.add_argument("-c", "--config", help="Path to client JSON config file")
    p_cli.add_argument("-v", "--verbose", action="store_true", help="Verbose debug logging")
    p_cli.set_defaults(func=cmd_client)

    # test-flags command
    p_flg = subparsers.add_parser("test-flags", help="Inspect and test raw TCP packets and TCP flags")
    p_flg.add_argument("--src-ip", default="127.0.0.1", help="Source IP")
    p_flg.add_argument("--dst-ip", default="127.0.0.1", help="Destination IP")
    p_flg.add_argument("--src-port", type=int, default=54321, help="Source port")
    p_flg.add_argument("--dst-port", type=int, default=8443, help="Destination port")
    p_flg.add_argument("--flags", default="FIN,URG,PSH", help="TCP flags (or profile name like XMAS_TREE, ALL_FLAGS)")
    p_flg.add_argument("--matrix", action="store_true", help="Run full matrix of flag tests")
    p_flg.add_argument("--simulate", action="store_true", default=True, help="Use simulated loopback engine")
    p_flg.add_argument("--json", action="store_true", help="Output matrix results as JSON")
    p_flg.set_defaults(func=cmd_test_flags)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
