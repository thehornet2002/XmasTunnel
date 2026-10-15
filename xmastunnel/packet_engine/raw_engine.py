import os
import platform
import socket
import sys
from typing import Dict, List, Optional, Tuple
from .flags import TCPFlag, TEST_PROFILES, flags_to_str, parse_flags
from .packet import IPv4Header, TCPHeader, RawTCPPacket


class RawEngineError(Exception):
    pass


class CapabilityReport:
    """Documents platform capabilities and limitations regarding raw sockets."""
    def __init__(self):
        self.os_name = platform.system()
        self.os_release = platform.release()
        self.can_create_raw = False
        self.can_send_raw_tcp = False
        self.error_detail = ""
        self.probe_capabilities()

    def probe_capabilities(self) -> None:
        if self.os_name == "Windows":
            try:
                import scapy.all
                self.can_create_raw = True
                self.can_send_raw_tcp = True
                self.error_detail = "Npcap / Scapy raw packet injection active on Windows."
            except Exception:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                    s.close()
                    self.can_create_raw = True
                    self.can_send_raw_tcp = False
                    self.error_detail = "Npcap required for raw TCP sending on Windows."
                except Exception as e:
                    self.can_create_raw = False
                    self.can_send_raw_tcp = False
                    self.error_detail = str(e)

        elif self.os_name == "Linux":
            # On Linux, CAP_NET_RAW / root is required.
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                s.close()
                self.can_create_raw = True
                self.can_send_raw_tcp = True
                self.error_detail = "Raw socket capabilities available (CAP_NET_RAW)."
            except PermissionError:
                self.can_create_raw = False
                self.can_send_raw_tcp = False
                self.error_detail = "Root privileges or CAP_NET_RAW capability required on Linux."
            except OSError as e:
                self.can_create_raw = False
                self.can_send_raw_tcp = False
                self.error_detail = str(e)
        else:
            self.error_detail = f"Platform {self.os_name} raw socket support requires elevated privileges."

    def to_dict(self) -> dict:
        return {
            "os_name": self.os_name,
            "os_release": self.os_release,
            "can_create_raw": self.can_create_raw,
            "can_send_raw_tcp": self.can_send_raw_tcp,
            "detail": self.error_detail,
        }


class RawPacketEngine:
    """
    Engine for crafting, testing, transmitting, and inspecting raw TCP packets
    with arbitrary TCP flags (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR).
    """

    def __init__(self, fallback_to_loopback: bool = True):
        self.capability = CapabilityReport()
        self.fallback_to_loopback = fallback_to_loopback
        self.captured_packets: List[RawTCPPacket] = []

    def craft_tcp_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        flags: TCPFlag,
        seq: int = 1000,
        ack_seq: int = 0,
        payload: bytes = b"",
    ) -> RawTCPPacket:
        """Constructs a RawTCPPacket with exact flag bits and auto-computed checksums."""
        ip_hdr = IPv4Header(src_ip=src_ip, dst_ip=dst_ip)
        tcp_hdr = TCPHeader(
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack_seq=ack_seq,
            flags=flags,
        )
        return RawTCPPacket(ip_header=ip_hdr, tcp_header=tcp_hdr, payload=payload)

    def send_packet(
        self,
        packet: RawTCPPacket,
        simulate: bool = False,
    ) -> Dict[str, any]:
        """
        Sends the raw packet using OS raw socket if supported and permitted,
        or captures it into test log.
        """
        raw_bytes = packet.build()
        verified = packet.verify_tcp_checksum()

        result = {
            "src": f"{packet.ip_header.src_ip}:{packet.tcp_header.src_port}",
            "dst": f"{packet.ip_header.dst_ip}:{packet.tcp_header.dst_port}",
            "flags": flags_to_str(packet.tcp_header.flags),
            "seq": packet.tcp_header.seq,
            "ack": packet.tcp_header.ack_seq,
            "raw_size": len(raw_bytes),
            "checksum_valid": verified,
            "status": "pending",
        }

        if simulate:
            self.captured_packets.append(packet)
            result["status"] = "simulated_success"
            result["mode"] = "isolated_engine"
            return result

        # 1. Try Scapy / Npcap (active on Windows with Npcap & on Linux)
        try:
            from scapy.all import IP, TCP, Raw, send
            from ..transport.raw_transport import flags_to_scapy
            flag_str = flags_to_str(packet.tcp_header.flags)
            scapy_f = flags_to_scapy(flag_str)
            src_ip = packet.ip_header.src_ip if packet.ip_header.src_ip not in ("0.0.0.0", "127.0.0.1") else None
            pkt = (
                IP(dst=packet.ip_header.dst_ip, src=src_ip)
                / TCP(
                    sport=packet.tcp_header.src_port,
                    dport=packet.tcp_header.dst_port,
                    flags=scapy_f,
                    seq=packet.tcp_header.seq,
                    ack=packet.tcp_header.ack_seq,
                )
                / Raw(load=packet.payload)
            )
            send(pkt, verbose=False)
            result["status"] = "live_sent_npcap"
            result["mode"] = "npcap_driver"
            return result
        except Exception:
            pass

        # 2. Fallback to OS raw socket (Linux SOCK_RAW)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.sendto(raw_bytes, (packet.ip_header.dst_ip, packet.tcp_header.dst_port))
            sock.close()
            result["status"] = "live_sent"
            result["mode"] = "os_raw_socket"
            return result
        except OSError as e:
            if self.fallback_to_loopback:
                self.captured_packets.append(packet)
                result["status"] = f"fallback_simulated ({e})"
                result["mode"] = "isolated_engine"
            else:
                raise RawEngineError(f"Failed to transmit raw packet: {e}") from e

        return result

    def run_flag_matrix_test(
        self,
        src_ip: str = "127.0.0.1",
        dst_ip: str = "127.0.0.1",
        src_port: int = 50001,
        dst_port: int = 8080,
    ) -> List[dict]:
        """
        Executes a matrix of TCP flag combination tests, verifying packet construction,
        header serialization, checksum integrity, and parsing roundtrips.
        """
        results = []
        for profile_name, flags in TEST_PROFILES.items():
            packet = self.craft_tcp_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                flags=flags,
                payload=f"TEST_PAYLOAD_{profile_name}".encode("ascii"),
            )

            # Test round-trip serialization & checksum validation
            raw_data = packet.build()
            parsed = RawTCPPacket.parse(raw_data)
            checksum_ok = packet.verify_tcp_checksum()

            flags_match = (parsed.tcp_header.flags == flags)
            payload_match = (parsed.payload == packet.payload)

            send_status = self.send_packet(packet, simulate=True)

            results.append({
                "profile": profile_name,
                "flags_set": flags_to_str(flags),
                "checksum_valid": checksum_ok,
                "roundtrip_flags_match": flags_match,
                "roundtrip_payload_match": payload_match,
                "total_bytes": len(raw_data),
                "send_status": send_status["status"],
            })

        return results
