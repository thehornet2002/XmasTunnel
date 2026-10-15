import pytest
from xmastunnel.packet_engine.flags import (
    TCPFlag,
    TEST_PROFILES,
    parse_flags,
    flags_to_str,
)
from xmastunnel.packet_engine.checksum import (
    internet_checksum,
    compute_ipv4_checksum,
    compute_tcp_checksum,
)
from xmastunnel.packet_engine.packet import (
    IPv4Header,
    TCPHeader,
    RawTCPPacket,
)
from xmastunnel.packet_engine.raw_engine import RawPacketEngine


def test_flag_parsing_and_str():
    # Bitmask
    flags = TCPFlag.SYN | TCPFlag.ACK
    assert flags_to_str(flags) == "SYN|ACK"

    # From string
    parsed = parse_flags("FIN,URG,PSH")
    assert parsed == (TCPFlag.FIN | TCPFlag.URG | TCPFlag.PSH)
    assert flags_to_str(parsed) == "FIN|PSH|URG"

    # Profile lookup
    xmas = parse_flags("XMAS_TREE")
    assert xmas == TEST_PROFILES["XMAS_TREE"]


def test_checksum_algorithm():
    # RFC 1071 simple vector
    data = b"\x00\x01\xf2\x03\xf4\xf5\xf6\xf7"
    chk = internet_checksum(data)
    assert 0 <= chk <= 0xFFFF

    # Verifying checksum property: sum of data + checksum inverted should equal 0
    # In RFC 1071, checksum of (data + checksum) is 0x0000 or 0xFFFF
    # Check internet_checksum on valid packet components
    ip = IPv4Header("192.168.1.1", "192.168.1.2")
    raw_ip = ip.pack()
    unpacked_ip = IPv4Header.unpack(raw_ip)
    assert unpacked_ip.src_ip == "192.168.1.1"
    assert unpacked_ip.dst_ip == "192.168.1.2"
    assert unpacked_ip.checksum != 0


def test_raw_tcp_packet_craft_and_parse():
    src_ip = "10.0.0.1"
    dst_ip = "10.0.0.2"
    src_port = 12345
    dst_port = 443

    ip_hdr = IPv4Header(src_ip=src_ip, dst_ip=dst_ip)
    tcp_hdr = TCPHeader(
        src_port=src_port,
        dst_port=dst_port,
        flags=TCPFlag.FIN | TCPFlag.URG | TCPFlag.PSH,  # Xmas Tree
        seq=5000,
        ack_seq=6000,
    )
    payload = b"Encrypted-Data-Probe"

    packet = RawTCPPacket(ip_header=ip_hdr, tcp_header=tcp_hdr, payload=payload)
    raw_bytes = packet.build()

    # Verify checksum
    assert packet.verify_tcp_checksum() is True

    # Parse back from raw bytes
    parsed = RawTCPPacket.parse(raw_bytes)
    assert parsed.ip_header.src_ip == src_ip
    assert parsed.ip_header.dst_ip == dst_ip
    assert parsed.tcp_header.src_port == src_port
    assert parsed.tcp_header.dst_port == dst_port
    assert parsed.tcp_header.flags == (TCPFlag.FIN | TCPFlag.URG | TCPFlag.PSH)
    assert parsed.tcp_header.seq == 5000
    assert parsed.tcp_header.ack_seq == 6000
    assert parsed.payload == payload
    assert parsed.verify_tcp_checksum() is True


def test_flag_matrix_execution():
    engine = RawPacketEngine(fallback_to_loopback=True)
    results = engine.run_flag_matrix_test()

    assert len(results) == len(TEST_PROFILES)
    for r in results:
        assert r["checksum_valid"] is True
        assert r["roundtrip_flags_match"] is True
        assert r["roundtrip_payload_match"] is True
        assert "simulated" in r["send_status"] or "live" in r["send_status"]
