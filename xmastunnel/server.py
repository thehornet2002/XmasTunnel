import logging
import socket
import struct
import threading
import time
from typing import Callable, Dict, Optional
from .config.config import ServerConfig
from .config.logger import setup_logger
from .crypto.kdf import generate_server_psk
from .protocol.frame import Frame, FrameType, ProtocolError
from .session.session import TunnelSession, SessionSecurityError
from .session.session_manager import SessionManager
from .transport.tcp_transport import (
    TCPConnection,
    TransportError,
    create_tcp_listener,
)


class TunnelServer:
    """
    Modular TCP Tunnel Server with AES-256-GCM encryption.
    """

    def __init__(
        self,
        config: ServerConfig,
        on_data_received: Optional[Callable[[TunnelSession, bytes], Optional[bytes]]] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.config = config
        self.logger = logger or setup_logger(
            "XmasTunnel.Server",
            level=logging.DEBUG if config.verbose else logging.INFO,
            log_file=config.log_file,
        )

        # Generate PSK if not provided
        if not self.config.psk:
            self.psk = generate_server_psk()
            self.logger.info("=" * 64)
            self.logger.info("GENERATED SERVER PRE-SHARED KEY (AES-256):")
            self.logger.info(self.psk)
            self.logger.info("Provide this key to clients to connect.")
            self.logger.info("=" * 64)
        else:
            self.psk = self.config.psk

        self.session_manager = SessionManager(
            max_sessions=config.max_sessions,
            idle_timeout=config.idle_timeout,
        )
        self.on_data_received = on_data_received or self._default_echo_handler

        self._listener_sock: Optional[socket.socket] = None
        self._running = False
        self._accept_thread: Optional[threading.Thread] = None
        self._client_threads: Dict[int, threading.Thread] = {}
        self._connections: Dict[int, TCPConnection] = {}
        self._lock = threading.Lock()

    def _default_echo_handler(self, session: TunnelSession, data: bytes) -> Optional[bytes]:
        """Default handler: echoes received data back with an ACK header."""
        return b"ACK:" + data

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self, blocking: bool = False) -> None:
        """Starts listening for incoming client tunnel connections."""
        self._running = True
        if getattr(self.config, "raw_mode", False):
            import platform, subprocess
            if platform.system() == "Linux":
                try:
                    subprocess.run(
                        ["iptables", "-I", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "--sport", str(self.config.port), "-j", "DROP"],
                        check=False,
                        stderr=subprocess.DEVNULL,
                    )
                    self.logger.info(f"[Raw Mode] Configured iptables rule to suppress kernel RST on port {self.config.port}")
                except Exception as e:
                    self.logger.warning(f"Could not apply iptables rule: {e}")

            self.logger.info(
                f"[Raw Mode] Server listening on {self.config.host}:{self.config.port} for Raw TCP Packets (TX Flags: {self.config.server_flags})"
            )
            self._accept_thread = threading.Thread(target=self._raw_accept_loop, daemon=True, name="RawAcceptLoop")
            self._accept_thread.start()
        else:
            self._listener_sock = create_tcp_listener(self.config.host, self.config.port)
            self.logger.info(f"Server listening on {self.config.host}:{self.config.port}")
            self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True, name="AcceptLoop")
            self._accept_thread.start()

        if blocking:
            try:
                while self._running:
                    self._accept_thread.join(timeout=1.0)
            except KeyboardInterrupt:
                self.logger.info("Keyboard interrupt received, stopping server...")
                self.stop()

    def _raw_accept_loop(self) -> None:
        from scapy.all import AsyncSniffer, IP, TCP, Raw
        from .transport.raw_transport import RawTunnelConnection

        active_clients: Dict[Tuple[str, int], RawTunnelConnection] = {}

        def _on_raw_pkt(pkt):
            try:
                if Raw in pkt and TCP in pkt and IP in pkt:
                    c_ip = pkt[IP].src
                    c_port = pkt[TCP].sport
                    key = (c_ip, c_port)
                    with self._lock:
                        conn = active_clients.get(key)
                        if conn is None:
                            self.logger.info(f"[Raw Mode] Detected new raw client from {c_ip}:{c_port}")
                            conn = RawTunnelConnection(
                                local_ip=self.config.host,
                                local_port=self.config.port,
                                remote_ip=c_ip,
                                remote_port=c_port,
                                tx_flags=self.config.server_flags,
                                start_sniffer=False,
                                logger=self.logger,
                            )
                            active_clients[key] = conn
                            t = threading.Thread(
                                target=self._handle_client,
                                args=(conn,),
                                daemon=True,
                                name=f"RawClient-{c_ip}:{c_port}",
                            )
                            t.start()

                    conn.feed_raw_packet(pkt[Raw].load)
            except Exception as e:
                self.logger.debug(f"Raw packet processing notice: {e}")

        try:
            sniffer = AsyncSniffer(
                filter=f"tcp and dst port {self.config.port}",
                prn=_on_raw_pkt,
                store=False,
            )
            sniffer.start()
            while self._running:
                time.sleep(1.0)
            sniffer.stop()
        except Exception as e:
            self.logger.warning(f"Raw sniffer loop error: {e}")

    def _accept_loop(self) -> None:
        while self._running:
            try:
                client_sock, addr = self._listener_sock.accept()
            except OSError:
                break

            self.logger.info(f"Accepted raw TCP connection from {addr[0]}:{addr[1]}")
            conn = TCPConnection(
                client_sock,
                rate_limit_bytes_per_sec=self.config.rate_limit_bytes_per_sec,
            )

            client_thread = threading.Thread(
                target=self._handle_client,
                args=(conn,),
                daemon=True,
                name=f"ClientWorker-{addr[0]}:{addr[1]}",
            )
            client_thread.start()

    def _handle_client(self, conn: TCPConnection) -> None:
        session: Optional[TunnelSession] = None
        try:
            # 1. Wait for HANDSHAKE_INIT (filtering out any stray pre-probe frames)
            init_frame = None
            start_wait = time.time()
            while time.time() - start_wait < 10.0:
                f = conn.recv_frame(timeout=2.0)
                if f and f.frame_type == FrameType.HANDSHAKE_INIT:
                    init_frame = f
                    break
            if not init_frame:
                self.logger.warning("Timeout or missing HANDSHAKE_INIT from client")
                return

            # Create server session
            session = self.session_manager.create_session(role="server", psk=self.psk)
            with self._lock:
                self._connections[session.session_id] = conn

            self.logger.debug(f"Handshake init from {conn.peer_address}, session_id=0x{session.session_id:016X}")

            # 2. Process INIT and send RESP
            resp_frame = session.handle_handshake_init(init_frame)
            conn.send_frame(resp_frame)

            # 3. Wait for HANDSHAKE_AUTH
            auth_frame = conn.recv_frame(timeout=10.0)
            if not auth_frame or auth_frame.frame_type != FrameType.HANDSHAKE_AUTH:
                self.logger.warning("Invalid or missing HANDSHAKE_AUTH")
                return

            # 4. Verify AUTH and send CONFIRM
            confirm_frame = session.handle_handshake_auth(auth_frame)
            conn.send_frame(confirm_frame)

            self.logger.info(
                f"Session 0x{session.session_id:016X} ESTABLISHED with {conn.peer_address} (AES-256-GCM)"
            )

            outbound_sockets: Dict[int, socket.socket] = {}
            outbound_lock = threading.Lock()

            def _relay_outbound_to_tunnel(sid: int, out_sock: socket.socket) -> None:
                try:
                    while self._running and session.is_established:
                        chunk = out_sock.recv(32768)
                        if not chunk:
                            break
                        stream_payload = struct.pack(">I", sid) + chunk
                        out_f = session.encrypt_frame(FrameType.STREAM_DATA, stream_payload)
                        conn.send_frame(out_f)
                except Exception:
                    pass
                finally:
                    with outbound_lock:
                        outbound_sockets.pop(sid, None)
                    try:
                        out_sock.close()
                    except OSError:
                        pass
                    try:
                        if session.is_established:
                            close_f = session.encrypt_frame(FrameType.STREAM_CLOSE, struct.pack(">I", sid))
                            conn.send_frame(close_f)
                    except Exception:
                        pass

            # 5. Established session loop
            while self._running and session.is_established:
                frame = conn.recv_frame(timeout=self.config.idle_timeout)
                if frame is None:
                    self.logger.info(f"Client {conn.peer_address} disconnected cleanly")
                    break

                if frame.frame_type == FrameType.STREAM_OPEN:
                    plaintext = session.decrypt_frame(frame)
                    if len(plaintext) >= 7:
                        stream_id, host_len, dst_port = struct.unpack(">IBH", plaintext[:7])
                        dst_host = plaintext[7:7+host_len].decode("utf-8", errors="replace")
                        self.logger.info(f"[Session 0x{session.session_id:016X}] SOCKS5 Stream #{stream_id} -> {dst_host}:{dst_port}")
                        try:
                            out_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            try:
                                out_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                            except OSError:
                                pass
                            out_sock.settimeout(10.0)
                            out_sock.connect((dst_host, dst_port))
                            out_sock.settimeout(None)
                            with outbound_lock:
                                outbound_sockets[stream_id] = out_sock
                            t_out = threading.Thread(
                                target=_relay_outbound_to_tunnel,
                                args=(stream_id, out_sock),
                                daemon=True,
                                name=f"SOCKS5-Out-{stream_id}",
                            )
                            t_out.start()
                        except Exception as e:
                            self.logger.warning(f"Failed to connect to {dst_host}:{dst_port}: {e}")
                            rst_payload = struct.pack(">I", stream_id)
                            rst_f = session.encrypt_frame(FrameType.STREAM_RESET, rst_payload)
                            conn.send_frame(rst_f)

                elif frame.frame_type == FrameType.STREAM_DATA:
                    plaintext = session.decrypt_frame(frame)
                    if len(plaintext) > 4:
                        stream_id = struct.unpack(">I", plaintext[:4])[0]
                        chunk = plaintext[4:]
                        with outbound_lock:
                            s_sock = outbound_sockets.get(stream_id)
                        if s_sock:
                            try:
                                s_sock.sendall(chunk)
                            except OSError:
                                with outbound_lock:
                                    outbound_sockets.pop(stream_id, None)
                                try:
                                    s_sock.close()
                                except OSError:
                                    pass

                elif frame.frame_type == FrameType.STREAM_CLOSE or frame.frame_type == FrameType.STREAM_RESET:
                    plaintext = session.decrypt_frame(frame)
                    if len(plaintext) >= 4:
                        stream_id = struct.unpack(">I", plaintext[:4])[0]
                        with outbound_lock:
                            s_sock = outbound_sockets.pop(stream_id, None)
                        if s_sock:
                            try:
                                s_sock.close()
                            except OSError:
                                pass

                elif frame.frame_type == FrameType.DATA:
                    plaintext = session.decrypt_frame(frame)
                    self.logger.debug(f"Received {len(plaintext)} plaintext bytes from session 0x{session.session_id:016X}")
                    reply = self.on_data_received(session, plaintext)
                    if reply:
                        out_frame = session.encrypt_frame(FrameType.DATA, reply)
                        conn.send_frame(out_frame)

                elif frame.frame_type == FrameType.PING:
                    session.decrypt_frame(frame)
                    pong_frame = session.encrypt_frame(FrameType.PONG, b"PONG")
                    conn.send_frame(pong_frame)

                elif frame.frame_type == FrameType.REKEY_REQUEST:
                    self.logger.info(f"Processing rekey request for session 0x{session.session_id:016X}")
                    ack_frame = session.handle_rekey_request(frame)
                    conn.send_frame(ack_frame)
                    self.logger.info(f"Session 0x{session.session_id:016X} keys rotated successfully")

                elif frame.frame_type == FrameType.TEARDOWN:
                    self.logger.info(f"Teardown received from session 0x{session.session_id:016X}")
                    break

        except SessionSecurityError as e:
            self.logger.error(f"Security error with {conn.peer_address}: {e}")
        except TransportError as e:
            self.logger.warning(f"Transport error with {conn.peer_address}: {e}")
        except Exception as e:
            self.logger.exception(f"Unexpected error handling client: {e}")
        finally:
            # Clean up any open outbound sockets
            try:
                for s in list(outbound_sockets.values()):
                    try:
                        s.close()
                    except OSError:
                        pass
                outbound_sockets.clear()
            except Exception:
                pass
            if session:
                with self._lock:
                    self._connections.pop(session.session_id, None)
                self.session_manager.remove_session(session.session_id)
            conn.close()

    def stop(self) -> None:
        """Stops the server listener and terminates all active sessions."""
        self._running = False
        if getattr(self.config, "raw_mode", False):
            import platform, subprocess
            if platform.system() == "Linux":
                try:
                    subprocess.run(
                        ["iptables", "-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "--sport", str(self.config.port), "-j", "DROP"],
                        check=False,
                        stderr=subprocess.DEVNULL,
                    )
                except Exception:
                    pass
        if self._listener_sock:
            try:
                self._listener_sock.close()
            except OSError:
                pass
        with self._lock:
            for sid, conn in list(self._connections.items()):
                conn.close()
            self._connections.clear()
        self.logger.info("Server stopped.")
