import socket
import struct


def internet_checksum(data: bytes) -> int:
    """
    Computes standard 16-bit One's Complement Internet Checksum (RFC 1071).
    """
    if len(data) % 2 == 1:
        data = data + b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word

    # Fold 32-bit sum into 16 bits
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)

    # One's complement
    return (~total) & 0xFFFF


def compute_ipv4_checksum(header_without_checksum: bytes) -> int:
    """Calculates IPv4 header checksum."""
    return internet_checksum(header_without_checksum)


def compute_tcp_checksum(
    src_ip: str,
    dst_ip: str,
    tcp_header_zero_checksum: bytes,
    payload: bytes = b"",
) -> int:
    """
    Computes 16-bit TCP checksum using IPv4 Pseudo-Header (RFC 793).
    Pseudo-Header format:
      - 4 bytes: Source IP Address
      - 4 bytes: Destination IP Address
      - 1 byte:  Zero (0x00)
      - 1 byte:  Protocol (6 for TCP)
      - 2 bytes: TCP Length (TCP Header + Payload)
    """
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    tcp_length = len(tcp_header_zero_checksum) + len(payload)

    pseudo_header = struct.pack(
        ">4s4sBBH",
        src_bytes,
        dst_bytes,
        0,
        socket.IPPROTO_TCP,
        tcp_length,
    )

    full_segment = pseudo_header + tcp_header_zero_checksum + payload
    return internet_checksum(full_segment)
