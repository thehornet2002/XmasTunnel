import pytest
from xmastunnel.protocol.frame import (
    Frame,
    FrameType,
    FrameParser,
    ProtocolError,
    HEADER_SIZE,
    MAGIC,
)
from xmastunnel.protocol.state_machine import (
    ProtocolState,
    ProtocolStateMachine,
    StateTransitionError,
)


def test_frame_pack_unpack_roundtrip():
    payload = b"Hello, encrypted tunnel framing!"
    frame = Frame(
        frame_type=FrameType.DATA,
        session_id=0x123456789ABCDEF0,
        seq=42,
        payload=payload,
    )

    packed = frame.pack()
    assert len(packed) == HEADER_SIZE + len(payload)

    version, ftype, session_id, seq, plen = Frame.unpack_header(packed[:HEADER_SIZE])
    assert ftype == FrameType.DATA
    assert session_id == 0x123456789ABCDEF0
    assert seq == 42
    assert plen == len(payload)


def test_frame_parser_fragmentation():
    parser = FrameParser()
    frame = Frame(FrameType.DATA, 100, 1, payload=b"CHUNKED_DATA_PACKET")
    data = frame.pack()

    # Feed in 5-byte pieces to simulate network fragmentation
    parsed_frame = None
    for i in range(0, len(data), 5):
        parser.feed(data[i:i+5])
        f = parser.next_frame()
        if f is not None:
            parsed_frame = f

    assert parsed_frame is not None
    assert parsed_frame.frame_type == FrameType.DATA
    assert parsed_frame.payload == b"CHUNKED_DATA_PACKET"
    assert parsed_frame.seq == 1


def test_frame_parser_multiple_frames_in_buffer():
    parser = FrameParser()
    f1 = Frame(FrameType.DATA, 1, 1, payload=b"First")
    f2 = Frame(FrameType.PING, 1, 2, payload=b"")

    combined = f1.pack() + f2.pack()
    parser.feed(combined)

    res1 = parser.next_frame()
    res2 = parser.next_frame()
    res3 = parser.next_frame()

    assert res1 is not None and res1.payload == b"First"
    assert res2 is not None and res2.frame_type == FrameType.PING
    assert res3 is None


def test_protocol_state_machine_valid_and_invalid():
    sm = ProtocolStateMachine()
    assert sm.state == ProtocolState.DISCONNECTED

    sm.transition_to(ProtocolState.HANDSHAKE_INIT_SENT)
    assert sm.state == ProtocolState.HANDSHAKE_INIT_SENT

    sm.transition_to(ProtocolState.HANDSHAKE_AUTH_SENT)
    sm.transition_to(ProtocolState.ESTABLISHED)
    assert sm.is_established() is True

    # Invalid jump from ESTABLISHED directly to HANDSHAKE_INIT_SENT
    with pytest.raises(StateTransitionError):
        sm.transition_to(ProtocolState.HANDSHAKE_INIT_SENT)

    sm.transition_to(ProtocolState.TERMINATING)
    sm.transition_to(ProtocolState.CLOSED)
    assert sm.state == ProtocolState.CLOSED
