import logging
import secrets
import time
from typing import Optional
from .config.config import ClientConfig
from .config.logger import setup_logger
from .protocol.frame import Frame, FrameType, ProtocolError
from .session.session import TunnelSession, SessionSecurityError
from .transport.tcp_transport import (
    TCPConnection,
    TransportError,
    connect_tcp,
)


class TunnelClient:
    """
    Client for establishing and managing an AES-256-GCM encrypted TCP tunnel.
    """

    def __init__(
        self,
        config: ClientConfig,
        logger: Optional[logging.Logger] = None,
    ):
        if not config.psk:
            raise ValueError("Pre-shared key (psk) must be provided to client")
        self.config = config
        self.logger = logger or setup_logger(
            "XmasTunnel.Client",
            level=logging.DEBUG if config.verbose else logging.INFO,
            log_file=config.log_file,
        )
        self.conn: Optional[TCPConnection] = None
        self.session: Optional[TunnelSession] = None

    @property
    def is_connected(self) -> bool:
        return self.conn is not None and self.session is not None and self.session.is_established

    def connect(self) -> None:
        """Connects to remote server and executes cryptographic handshake."""
        self.logger.info(f"Connecting to {self.config.remote_host}:{self.config.remote_port}...")
        self.conn = connect_tcp(
            host=self.config.remote_host,
            port=self.config.remote_port,
            timeout=self.config.timeout,
            retry_count=self.config.retry_count,
            retry_delay=self.config.retry_delay,
            rate_limit=self.config.rate_limit_bytes_per_sec,
        )

        session_id = secrets.randbits(63)
        self.session = TunnelSession(
            session_id=session_id,
            role="client",
            psk=self.config.psk,
        )

        # Step 1: Send HANDSHAKE_INIT
        self.logger.debug("Initiating tunnel handshake...")
        init_frame = self.session.create_handshake_init()
        self.conn.send_frame(init_frame)

        # Step 2: Receive HANDSHAKE_RESP
        resp_frame = self.conn.recv_frame(timeout=self.config.timeout)
        if not resp_frame or resp_frame.frame_type != FrameType.HANDSHAKE_RESP:
            raise ProtocolError(f"Expected HANDSHAKE_RESP, got {resp_frame}")

        # Step 3: Compute session keys and send HANDSHAKE_AUTH
        auth_frame = self.session.handle_handshake_resp(resp_frame)
        self.conn.send_frame(auth_frame)

        # Step 4: Receive HANDSHAKE_CONFIRM
        confirm_frame = self.conn.recv_frame(timeout=self.config.timeout)
        if not confirm_frame or confirm_frame.frame_type != FrameType.HANDSHAKE_CONFIRM:
            raise ProtocolError(f"Expected HANDSHAKE_CONFIRM, got {confirm_frame}")

        self.session.handle_handshake_confirm(confirm_frame)
        self.logger.info(
            f"Tunnel established successfully! Session ID: 0x{self.session.session_id:016X} (AES-256-GCM)"
        )

    def send_data(self, data: bytes) -> None:
        """Encrypts and transmits application payload."""
        if not self.is_connected:
            raise TransportError("Tunnel is not connected or established")

        # Check if rekey threshold reached
        if self.session.should_rekey():
            self.logger.info("Rekey threshold reached, triggering key rotation...")
            self.rekey()

        frame = self.session.encrypt_frame(FrameType.DATA, data)
        self.conn.send_frame(frame)

    def recv_data(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """Receives next data frame, decrypts and returns plaintext."""
        if not self.is_connected:
            raise TransportError("Tunnel is not connected or established")

        while True:
            frame = self.conn.recv_frame(timeout=timeout)
            if frame is None:
                return None

            if frame.frame_type == FrameType.DATA:
                return self.session.decrypt_frame(frame)

            elif frame.frame_type == FrameType.PING:
                self.session.decrypt_frame(frame)
                pong = self.session.encrypt_frame(FrameType.PONG, b"PONG")
                self.conn.send_frame(pong)

            elif frame.frame_type == FrameType.PONG:
                self.session.decrypt_frame(frame)
                # Pong consumed internally

            elif frame.frame_type == FrameType.TEARDOWN:
                self.logger.info("Server sent teardown notification")
                self.close()
                return None

    def ping(self, timeout: float = 5.0) -> float:
        """Sends encrypted PING and measures round trip time in milliseconds."""
        if not self.is_connected:
            raise TransportError("Tunnel is not connected")

        t_start = time.perf_counter()
        ping_frame = self.session.encrypt_frame(FrameType.PING, b"PING")
        self.conn.send_frame(ping_frame)

        frame = self.conn.recv_frame(timeout=timeout)
        t_end = time.perf_counter()
        if not frame or frame.frame_type != FrameType.PONG:
            raise ProtocolError(f"Expected PONG response, got {frame}")

        self.session.decrypt_frame(frame)
        return (t_end - t_start) * 1000.0

    def rekey(self) -> None:
        """Initiates on-demand or periodic key rotation."""
        if not self.is_connected:
            raise TransportError("Cannot rekey unconnected tunnel")

        self.logger.debug("Sending rekey request...")
        rekey_frame = self.session.create_rekey_request()
        self.conn.send_frame(rekey_frame)

        ack_frame = self.conn.recv_frame(timeout=self.config.timeout)
        if not ack_frame or ack_frame.frame_type != FrameType.REKEY_ACK:
            raise ProtocolError(f"Expected REKEY_ACK, got {ack_frame}")

        self.session.handle_rekey_ack(ack_frame)
        self.logger.info("Session keys rotated successfully.")

    def close(self) -> None:
        """Gracefully terminates tunnel."""
        if self.session and self.session.is_established and self.conn:
            try:
                teardown = self.session.create_teardown()
                self.conn.send_frame(teardown)
            except Exception:
                pass
        if self.session:
            self.session.close()
        if self.conn:
            self.conn.close()
        self.logger.info("Tunnel closed.")
