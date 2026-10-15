import enum
import struct
from typing import Optional, Tuple


MAGIC = b"XT"
PROTOCOL_VERSION = 1
HEADER_STRUCT_FORMAT = ">2sBBQQI"  # magic(2), version(1), type(1), session_id(8), seq(8), length(4)
HEADER_SIZE = struct.calcsize(HEADER_STRUCT_FORMAT)  # 24 bytes
MAX_FRAME_PAYLOAD_SIZE = 65536  # 64 KB safety limit


class FrameType(enum.IntEnum):
    HANDSHAKE_INIT = 0x01
    HANDSHAKE_RESP = 0x02
    HANDSHAKE_AUTH = 0x03
    HANDSHAKE_CONFIRM = 0x04
    DATA = 0x10
    STREAM_OPEN = 0x11       # Request remote server connect to dst:port
    STREAM_DATA = 0x12       # Multiplexed TCP stream payload
    STREAM_CLOSE = 0x13      # Clean stream teardown
    STREAM_RESET = 0x14      # Error or abort stream
    PING = 0x20
    PONG = 0x21
    REKEY_REQUEST = 0x30
    REKEY_ACK = 0x31
    TEARDOWN = 0xFF


class ProtocolError(Exception):
    """Raised when protocol invariants or frame formats are violated."""
    pass


class Frame:
    """
    Represents a protocol frame.
    Header:
      - 2 bytes: Magic (b'XT')
      - 1 byte:  Protocol Version (1)
      - 1 byte:  FrameType
      - 8 bytes: Session ID (uint64)
      - 8 bytes: Sequence Number (uint64)
      - 4 bytes: Payload Length (uint32)
    Total Header: 24 bytes (also used as AEAD Additional Authenticated Data)
    Followed by payload (bytes).
    """

    def __init__(
        self,
        frame_type: FrameType,
        session_id: int,
        seq: int,
        payload: bytes = b"",
        version: int = PROTOCOL_VERSION,
    ):
        if len(payload) > MAX_FRAME_PAYLOAD_SIZE:
            raise ProtocolError(
                f"Payload size {len(payload)} exceeds maximum allowed {MAX_FRAME_PAYLOAD_SIZE}"
            )
        self.version = version
        self.frame_type = FrameType(frame_type)
        self.session_id = session_id
        self.seq = seq
        self.payload = payload

    def pack_header(self) -> bytes:
        return struct.pack(
            HEADER_STRUCT_FORMAT,
            MAGIC,
            self.version,
            int(self.frame_type),
            self.session_id,
            self.seq,
            len(self.payload),
        )

    def pack(self) -> bytes:
        return self.pack_header() + self.payload

    @classmethod
    def unpack_header(cls, header_bytes: bytes) -> Tuple[int, FrameType, int, int, int]:
        """
        Returns (version, frame_type, session_id, seq, payload_len).
        """
        if len(header_bytes) != HEADER_SIZE:
            raise ProtocolError(f"Header must be {HEADER_SIZE} bytes, got {len(header_bytes)}")

        magic, version, ftype, session_id, seq, length = struct.unpack(
            HEADER_STRUCT_FORMAT, header_bytes
        )
        if magic != MAGIC:
            raise ProtocolError(f"Invalid frame magic: {magic!r}")
        if version != PROTOCOL_VERSION:
            raise ProtocolError(f"Unsupported protocol version: {version}")
        try:
            frame_type = FrameType(ftype)
        except ValueError:
            raise ProtocolError(f"Unknown frame type: {ftype}")
        if length > MAX_FRAME_PAYLOAD_SIZE:
            raise ProtocolError(f"Frame length {length} exceeds maximum {MAX_FRAME_PAYLOAD_SIZE}")

        return version, frame_type, session_id, seq, length


class FrameParser:
    """
    Stream buffer parser for assembling complete Frames from arbitrary TCP stream chunks.
    """

    def __init__(self, max_payload_size: int = MAX_FRAME_PAYLOAD_SIZE):
        self._buffer = bytearray()
        self._max_payload_size = max_payload_size

    def feed(self, data: bytes) -> None:
        self._buffer.extend(data)

    def next_frame(self) -> Optional[Frame]:
        """Extract the next complete frame, or None if more data is needed."""
        while len(self._buffer) >= HEADER_SIZE:
            # Find magic in buffer
            idx = self._buffer.find(MAGIC)
            if idx == -1:
                # No magic in buffer; keep only the last byte in case MAGIC is split
                del self._buffer[:-1]
                return None
            elif idx > 0:
                # Discard non-frame bytes before MAGIC
                del self._buffer[:idx]
                if len(self._buffer) < HEADER_SIZE:
                    return None

            header_bytes = bytes(self._buffer[:HEADER_SIZE])
            try:
                version, frame_type, session_id, seq, payload_len = Frame.unpack_header(header_bytes)
            except ProtocolError:
                # Corrupted header, skip one byte and re-scan
                del self._buffer[0]
                continue

            total_frame_len = HEADER_SIZE + payload_len
            if len(self._buffer) < total_frame_len:
                return None  # Wait for remaining payload

            payload = bytes(self._buffer[HEADER_SIZE:total_frame_len])
            del self._buffer[:total_frame_len]

            return Frame(
                frame_type=frame_type,
                session_id=session_id,
                seq=seq,
                payload=payload,
                version=version,
            )

        return None

    def clear(self) -> None:
        self._buffer.clear()
