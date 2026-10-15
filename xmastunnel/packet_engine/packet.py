import socket
import struct
from typing import Optional, Tuple
from .checksum import compute_ipv4_checksum, compute_tcp_checksum, internet_checksum
from .flags import TCPFlag, flags_to_str


class IPv4Header:
    """
    Standard 20-byte IPv4 Header (RFC 791).
    """
    STRUCT_FORMAT = ">BBHHHBBH4s4s"

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        identification: int = 54321,
        ttl: int = 64,
        protocol: int = socket.IPPROTO_TCP,
        tos: int = 0,
        flags_and_offset: int = 0x4000,  # Don't fragment flag
    ):
        self.version = 4
        self.ihl = 5  # 5 32-bit words = 20 bytes
        self.tos = tos
        self.total_length = 20
        self.identification = identification
        self.flags_and_offset = flags_and_offset
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = 0
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    def pack(self, payload_length: int = 0) -> bytes:
        self.total_length = 20 + payload_length
        v_ihl = (self.version << 4) + self.ihl
        src_bytes = socket.inet_aton(self.src_ip)
        dst_bytes = socket.inet_aton(self.dst_ip)

        # First pack with checksum = 0
        raw_zero_chk = struct.pack(
            self.STRUCT_FORMAT,
            v_ihl,
            self.tos,
            self.total_length,
            self.identification,
            self.flags_and_offset,
            self.ttl,
            self.protocol,
            0,
            src_bytes,
            dst_bytes,
        )

        self.checksum = compute_ipv4_checksum(raw_zero_chk)

        # Repack with computed checksum
        return struct.pack(
            self.STRUCT_FORMAT,
            v_ihl,
            self.tos,
            self.total_length,
            self.identification,
            self.flags_and_offset,
            self.ttl,
            self.protocol,
            self.checksum,
            src_bytes,
            dst_bytes,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "IPv4Header":
        if len(data) < 20:
            raise ValueError("IPv4 header data must be at least 20 bytes")
        v_ihl, tos, total_length, ident, flags_off, ttl, proto, chk, src_b, dst_b = (
            struct.unpack(cls.STRUCT_FORMAT, data[:20])
        )
        version = v_ihl >> 4
        ihl = v_ihl & 0x0F
        if version != 4:
            raise ValueError(f"Not an IPv4 packet (version={version})")

        header = cls(
            src_ip=socket.inet_ntoa(src_b),
            dst_ip=socket.inet_ntoa(dst_b),
            identification=ident,
            ttl=ttl,
            protocol=proto,
            tos=tos,
            flags_and_offset=flags_off,
        )
        header.total_length = total_length
        header.checksum = chk
        header.ihl = ihl
        return header


class TCPHeader:
    """
    Standard 20-byte TCP Header (RFC 793).
    """
    STRUCT_FORMAT = ">HHIIBBHHH"

    def __init__(
        self,
        src_port: int,
        dst_port: int,
        seq: int = 1000,
        ack_seq: int = 0,
        flags: TCPFlag = TCPFlag.SYN,
        window: int = 64240,
        urg_ptr: int = 0,
        data_offset: int = 5,  # 5 * 4 = 20 bytes
    ):
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq = seq
        self.ack_seq = ack_seq
        self.data_offset = data_offset
        self.flags = TCPFlag(flags)
        self.window = window
        self.checksum = 0
        self.urg_ptr = urg_ptr

    def pack(self, src_ip: str, dst_ip: str, payload: bytes = b"") -> bytes:
        data_offset_reserved = (self.data_offset << 4)
        flags_int = int(self.flags)

        raw_zero_chk = struct.pack(
            self.STRUCT_FORMAT,
            self.src_port,
            self.dst_port,
            self.seq,
            self.ack_seq,
            data_offset_reserved,
            flags_int,
            self.window,
            0,
            self.urg_ptr,
        )

        self.checksum = compute_tcp_checksum(src_ip, dst_ip, raw_zero_chk, payload)

        return struct.pack(
            self.STRUCT_FORMAT,
            self.src_port,
            self.dst_port,
            self.seq,
            self.ack_seq,
            data_offset_reserved,
            flags_int,
            self.window,
            self.checksum,
            self.urg_ptr,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "TCPHeader":
        if len(data) < 20:
            raise ValueError("TCP header data must be at least 20 bytes")
        src_port, dst_port, seq, ack_seq, doff_res, flags_int, window, chk, urg_ptr = (
            struct.unpack(cls.STRUCT_FORMAT, data[:20])
        )
        data_offset = doff_res >> 4
        header = cls(
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack_seq=ack_seq,
            flags=TCPFlag(flags_int),
            window=window,
            urg_ptr=urg_ptr,
            data_offset=data_offset,
        )
        header.checksum = chk
        return header


class RawTCPPacket:
    """
    Combined IPv4 + TCP raw network packet.
    """

    def __init__(
        self,
        ip_header: IPv4Header,
        tcp_header: TCPHeader,
        payload: bytes = b"",
    ):
        self.ip_header = ip_header
        self.tcp_header = tcp_header
        self.payload = payload

    def build(self) -> bytes:
        """Constructs full raw IP packet with correct TCP and IP checksums."""
        tcp_bytes = self.tcp_header.pack(
            self.ip_header.src_ip, self.ip_header.dst_ip, self.payload
        )
        ip_bytes = self.ip_header.pack(payload_length=len(tcp_bytes) + len(self.payload))
        return ip_bytes + tcp_bytes + self.payload

    @classmethod
    def parse(cls, raw_bytes: bytes) -> "RawTCPPacket":
        """Parses raw IP packet into IPv4Header, TCPHeader, and payload."""
        ip = IPv4Header.unpack(raw_bytes)
        ip_hdr_len = ip.ihl * 4
        tcp_bytes = raw_bytes[ip_hdr_len:]
        tcp = TCPHeader.unpack(tcp_bytes)
        tcp_hdr_len = tcp.data_offset * 4
        payload = tcp_bytes[tcp_hdr_len:]
        return cls(ip_header=ip, tcp_header=tcp, payload=payload)

    def verify_tcp_checksum(self) -> bool:
        """Validates TCP checksum against IPv4 pseudo-header."""
        expected = self.tcp_header.checksum
        tcp_bytes = self.tcp_header.pack(
            self.ip_header.src_ip, self.ip_header.dst_ip, self.payload
        )
        calculated = struct.unpack(">H", tcp_bytes[16:18])[0]
        return expected == calculated

    def __repr__(self) -> str:
        flags_str = flags_to_str(self.tcp_header.flags)
        return (
            f"<RawTCPPacket {self.ip_header.src_ip}:{self.tcp_header.src_port} -> "
            f"{self.ip_header.dst_ip}:{self.tcp_header.dst_port} "
            f"Flags=[{flags_str}] Seq={self.tcp_header.seq} Ack={self.tcp_header.ack_seq} "
            f"PayloadLen={len(self.payload)}>"
        )
