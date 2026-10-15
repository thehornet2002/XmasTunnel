import argparse
import json
import sys
import time
from .config.config import (
    ServerConfig,
    ClientConfig,
    load_server_config,
    load_client_config,
)
from .config.logger import setup_logger
from .crypto.kdf import generate_server_psk
from .packet_engine.flags import TEST_PROFILES, parse_flags, flags_to_str
from .packet_engine.raw_engine import RawPacketEngine, CapabilityReport
from .server import TunnelServer
from .client import TunnelClient


def cmd_gen_key(args: argparse.Namespace) -> None:
    psk = generate_server_psk()
    print("=" * 64)
    print("NEW RANDOM 256-BIT PRE-SHARED KEY (HEX):")
    print(psk)
    print("=" * 64)


def cmd_server(args: argparse.Namespace) -> None:
    if args.config:
        config = load_server_config(args.config)
    else:
        config = ServerConfig(
            host=args.host,
            port=args.port,
            psk=args.key,
            rate_limit_bytes_per_sec=args.rate_limit,
            verbose=args.verbose,
        )

    server = TunnelServer(config)
    print(f"[*] Starting XmasTunnel Server on {config.host}:{config.port}...")
    server.start(blocking=True)


def cmd_client(args: argparse.Namespace) -> None:
    if args.config:
        config = load_client_config(args.config)
    else:
        if not args.key:
            print("[!] Error: --key is required to connect to server.", file=sys.stderr)
            sys.exit(1)
        config = ClientConfig(
            remote_host=args.server,
            remote_port=args.port,
            psk=args.key,
            rate_limit_bytes_per_sec=args.rate_limit,
            verbose=args.verbose,
        )

    client = TunnelClient(config)
    try:
        if getattr(args, "xmas_probe", False):
            print("[*] Dispatching Xmas Tree probe packet (FIN|PSH|URG) to server...")
            engine = RawPacketEngine(fallback_to_loopback=True)
            probe_pkt = engine.craft_tcp_packet(
                src_ip="127.0.0.1",
                dst_ip=args.server,
                src_port=54321,
                dst_port=args.port,
                flags=parse_flags("XMAS_TREE"),
                payload=b"XMAS_PROBE_HEADER",
            )
            probe_res = engine.send_packet(probe_pkt, simulate=True)
            print(f"[+] Xmas Probe Status: {probe_res['status']} | Flags: {probe_res['flags']} | Checksum Valid: {probe_res['checksum_valid']}")

        client.connect()
        if args.ping:
            print("[*] Running ping latency checks...")
            for i in range(args.ping):
                rtt = client.ping()
                print(f"[*] Ping #{i+1}: RTT = {rtt:.2f} ms")
                time.sleep(0.5)

        if args.send:
            payload = args.send.encode("utf-8")
            print(f"[*] Sending: {args.send}")
            client.send_data(payload)
            response = client.recv_data(timeout=5.0)
            if response:
                print(f"[+] Received: {response.decode('utf-8', errors='replace')}")
            else:
                print("[-] No response received.")

        if not args.ping and not args.send:
            print("[+] Tunnel is open. Type text and press Enter to send over encrypted tunnel (Ctrl+C to quit):")
            while True:
                line = input("> ")
                if not line:
                    continue
                client.send_data(line.encode("utf-8"))
                resp = client.recv_data(timeout=5.0)
                if resp:
                    print(f"< {resp.decode('utf-8', errors='replace')}")
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
    p_srv.add_argument("--host", default="0.0.0.0", help="Listen host (default: 0.0.0.0)")
    p_srv.add_argument("-p", "--port", type=int, default=8443, help="Listen port (default: 8443)")
    p_srv.add_argument("--key", default=None, help="Pre-shared key (generated automatically if omitted)")
    p_srv.add_argument("--rate-limit", type=int, default=0, help="Rate limit bytes/sec (0 = unlimited)")
    p_srv.add_argument("-c", "--config", help="Path to server JSON config file")
    p_srv.add_argument("-v", "--verbose", action="store_true", help="Verbose debug logging")
    p_srv.set_defaults(func=cmd_server)

    # client command
    p_cli = subparsers.add_parser("client", help="Start the tunnel client")
    p_cli.add_argument("-s", "--server", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    p_cli.add_argument("-p", "--port", type=int, default=8443, help="Server port (default: 8443)")
    p_cli.add_argument("--key", default="", help="Pre-shared key")
    p_cli.add_argument("--send", help="Send a single message and print response")
    p_cli.add_argument("--ping", type=int, metavar="COUNT", help="Send N ping frames and report RTT")
    p_cli.add_argument("--xmas-probe", action="store_true", help="Send Xmas Tree probe packet (FIN|PSH|URG) before connecting")
    p_cli.add_argument("--rate-limit", type=int, default=0, help="Rate limit bytes/sec (0 = unlimited)")
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
