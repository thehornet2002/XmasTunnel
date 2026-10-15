import logging
import secrets
import struct
import threading
import time
from typing import Optional
from .config.config import ClientConfig
from .config.logger import setup_logger
from .protocol.frame import Frame, FrameType, ProtocolError
from .session.session import TunnelSession, SessionSecurityError, CryptoError
from .transport.tcp_transport import (
    TCPConnection,
    TransportError,
    ConnectionTimeoutError,
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

    def send_raw_probe(self, count: int = 2) -> None:
        """Sends live raw TCP packets with configured flags (e.g. FIN|PSH|URG / Xmas) on the wire."""
        try:
            from scapy.all import IP, TCP, Raw, send
            from .transport.raw_transport import flags_to_scapy
            flags_sc = flags_to_scapy(getattr(self.config, "client_flags", "XMAS_TREE"))
            for _ in range(count):
                pkt = (
                    IP(dst=self.config.remote_host)
                    / TCP(
                        sport=secrets.randbelow(50000) + 10000,
                        dport=self.config.remote_port,
                        flags=flags_sc,
                    )
                    / Raw(load=b"XMAS_PACKET_WIRE_PROBE")
                )
                send(pkt, verbose=False)
        except Exception as e:
            self.logger.debug(f"Raw probe notice: {e}")

    def connect(self) -> None:
        """Connects to remote server and executes cryptographic handshake."""
        self.logger.info(f"Connecting to {self.config.remote_host}:{self.config.remote_port}...")
        if getattr(self.config, "raw_mode", False):
            from .transport.raw_transport import RawTunnelConnection
            self.logger.info(
                f"[Raw Mode] Using direct Raw TCP packets (Flags: {self.config.client_flags})"
            )
            self.conn = RawTunnelConnection(
                local_ip="0.0.0.0",
                local_port=54321,
                remote_ip=self.config.remote_host,
                remote_port=self.config.remote_port,
                tx_flags=self.config.client_flags,
                timeout=self.config.timeout,
                logger=self.logger,
            )
        else:
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

    def start_socks_proxy(self, listen_host: str = "127.0.0.1", listen_port: int = 10829) -> None:
        """Starts local SOCKS5 proxy and multiplexes connections over the encrypted tunnel."""
        if not self.is_connected:
            raise TransportError("Cannot start SOCKS5 proxy: tunnel is not connected")

        from .socks.socks_server import SOCKS5ProxyServer

        def on_open_stream(stream_id: int, dst_host: str, dst_port: int) -> bool:
            try:
                host_bytes = dst_host.encode("utf-8")
                payload = struct.pack(">IBH", stream_id, len(host_bytes), dst_port) + host_bytes
                f = self.session.encrypt_frame(FrameType.STREAM_OPEN, payload)
                self.conn.send_frame(f)
                return True
            except Exception as e:
                self.logger.warning(f"Failed to send STREAM_OPEN for stream #{stream_id}: {e}")
                return False

        def on_stream_data(stream_id: int, chunk: bytes) -> None:
            try:
                payload = struct.pack(">I", stream_id) + chunk
                f = self.session.encrypt_frame(FrameType.STREAM_DATA, payload)
                self.conn.send_frame(f)
            except Exception as e:
                self.logger.debug(f"Failed to send STREAM_DATA for stream #{stream_id}: {e}")

        def on_close_stream(stream_id: int) -> None:
            try:
                payload = struct.pack(">I", stream_id)
                f = self.session.encrypt_frame(FrameType.STREAM_CLOSE, payload)
                self.conn.send_frame(f)
            except Exception:
                pass

        self.socks_proxy = SOCKS5ProxyServer(
            listen_host=listen_host,
            listen_port=listen_port,
            on_open_stream=on_open_stream,
            on_stream_data=on_stream_data,
            on_close_stream=on_close_stream,
            logger=self.logger,
        )
        self.socks_proxy.start()

        self._socks_rx_thread = threading.Thread(
            target=self._socks_rx_loop, daemon=True, name="SOCKS5-Tunnel-RX"
        )
        self._socks_rx_thread.start()

    def _socks_rx_loop(self) -> None:
        last_ping = time.time()
        try:
            while self.is_connected and not getattr(self.conn, "_closed", False):
                try:
                    frame = self.conn.recv_frame(timeout=5.0)
                except ConnectionTimeoutError:
                    now = time.time()
                    if now - last_ping >= 15.0 and self.is_connected:
                        last_ping = now
                        try:
                            ping_f = self.session.encrypt_frame(FrameType.PING, b"PING")
                            self.conn.send_frame(ping_f)
                        except Exception:
                            pass
                    continue

                if frame is None:
                    break

                try:
                    if frame.frame_type == FrameType.STREAM_DATA:
                        plaintext = self.session.decrypt_frame(frame)
                        if len(plaintext) > 4:
                            stream_id = struct.unpack(">I", plaintext[:4])[0]
                            data = plaintext[4:]
                            if hasattr(self, "socks_proxy"):
                                self.socks_proxy.deliver_remote_data(stream_id, data)
                    elif frame.frame_type == FrameType.STREAM_CLOSE or frame.frame_type == FrameType.STREAM_RESET:
                        plaintext = self.session.decrypt_frame(frame)
                        if len(plaintext) >= 4:
                            stream_id = struct.unpack(">I", plaintext[:4])[0]
                            if hasattr(self, "socks_proxy"):
                                self.socks_proxy.close_stream(stream_id)
                    elif frame.frame_type == FrameType.PING:
                        self.session.decrypt_frame(frame)
                        pong = self.session.encrypt_frame(FrameType.PONG, b"PONG")
                        self.conn.send_frame(pong)
                    elif frame.frame_type == FrameType.PONG:
                        self.session.decrypt_frame(frame)
                    elif frame.frame_type == FrameType.TEARDOWN:
                        break
                except (SessionSecurityError, CryptoError) as e:
                    self.logger.warning(f"Decryption warning on frame: {e}")
                    continue
        except Exception as e:
            self.logger.debug(f"Tunnel RX loop ended: {e}")
        finally:
            if hasattr(self, "socks_proxy"):
                self.socks_proxy.stop()

    def close(self) -> None:
        """Gracefully terminates tunnel."""
        if hasattr(self, "socks_proxy"):
            try:
                self.socks_proxy.stop()
            except Exception:
                pass
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
