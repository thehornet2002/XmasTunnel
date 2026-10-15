import logging
import socket
import struct
import threading
from typing import Callable, Dict, Optional, Tuple


class SOCKS5ProxyServer:
    """
    Local SOCKS5 proxy server (RFC 1928).
    Listens on local interface (e.g. 127.0.0.1:10829), accepts browser/app connections,
    and bridges them over the XmasTunnel encrypted connection multiplexer.
    """

    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 10829,
        on_open_stream: Optional[Callable[[int, str, int], bool]] = None,
        on_stream_data: Optional[Callable[[int, bytes], None]] = None,
        on_close_stream: Optional[Callable[[int], None]] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.on_open_stream = on_open_stream
        self.on_stream_data = on_stream_data
        self.on_close_stream = on_close_stream
        self.logger = logger or logging.getLogger("XmasTunnel.SOCKS5")

        self._server_sock: Optional[socket.socket] = None
        self._running = False
        self._accept_thread: Optional[threading.Thread] = None
        self._next_stream_id = 1
        self._streams_lock = threading.Lock()
        self._streams: Dict[int, socket.socket] = {}

    def start(self) -> None:
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.listen_host, self.listen_port))
        self._server_sock.listen(128)
        self._running = True

        self.logger.info(f"SOCKS5 Proxy server listening on {self.listen_host}:{self.listen_port}")
        self._accept_thread = threading.Thread(
            target=self._accept_loop, daemon=True, name="SOCKS5-Accept"
        )
        self._accept_thread.start()

    def _accept_loop(self) -> None:
        while self._running:
            try:
                client_sock, addr = self._server_sock.accept()
            except OSError:
                break

            t = threading.Thread(
                target=self._handle_client,
                args=(client_sock,),
                daemon=True,
                name=f"SOCKS5-Client-{addr}",
            )
            t.start()

    def _handle_client(self, client_sock: socket.socket) -> None:
        stream_id = 0
        try:
            try:
                client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            client_sock.settimeout(15.0)

            # 1. SOCKS5 Greeting & Method Negotiation
            greeting = client_sock.recv(257)
            if not greeting or greeting[0] != 0x05:
                client_sock.close()
                return

            nmethods = greeting[1]
            # Reply 0x05, 0x00: NO AUTHENTICATION REQUIRED
            client_sock.sendall(b"\x05\x00")

            # 2. SOCKS5 Request
            req = client_sock.recv(4)
            if len(req) < 4 or req[0] != 0x05:
                client_sock.close()
                return

            cmd = req[1]
            if cmd != 0x01:  # Only CONNECT is supported
                # Command not supported (0x07)
                client_sock.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                client_sock.close()
                return

            atyp = req[3]
            dst_host = ""
            if atyp == 0x01:  # IPv4
                addr_bytes = client_sock.recv(4)
                dst_host = socket.inet_ntoa(addr_bytes)
            elif atyp == 0x03:  # Domain Name
                len_byte = client_sock.recv(1)
                domain_len = len_byte[0]
                dst_host = client_sock.recv(domain_len).decode("utf-8", errors="replace")
            elif atyp == 0x04:  # IPv6
                addr_bytes = client_sock.recv(16)
                dst_host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                client_sock.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                client_sock.close()
                return

            port_bytes = client_sock.recv(2)
            dst_port = struct.unpack(">H", port_bytes)[0]

            # 3. Allocate unique stream ID and register
            with self._streams_lock:
                stream_id = self._next_stream_id
                self._next_stream_id += 1
                self._streams[stream_id] = client_sock

            self.logger.info(
                f"[SOCKS5 Stream #{stream_id}] Proxying request to {dst_host}:{dst_port}"
            )

            # 4. Open stream through XmasTunnel
            opened = True
            if self.on_open_stream:
                opened = self.on_open_stream(stream_id, dst_host, dst_port)

            if not opened:
                # Connection refused / host unreachable (0x04 / 0x05)
                client_sock.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                client_sock.close()
                with self._streams_lock:
                    self._streams.pop(stream_id, None)
                return

            # Reply Success (0x00)
            client_sock.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            client_sock.settimeout(None)

            # 5. Read loop: forward local app bytes into encrypted tunnel
            while self._running:
                chunk = client_sock.recv(32768)
                if not chunk:
                    break
                if self.on_stream_data:
                    self.on_stream_data(stream_id, chunk)

        except Exception as e:
            self.logger.debug(f"[SOCKS5 Stream #{stream_id}] Closed with error: {e}")
        finally:
            with self._streams_lock:
                self._streams.pop(stream_id, None)
            try:
                client_sock.close()
            except OSError:
                pass
            if stream_id and self.on_close_stream:
                self.on_close_stream(stream_id)

    def deliver_remote_data(self, stream_id: int, data: bytes) -> bool:
        """Called when tunnel receives data from remote destination for a local stream."""
        with self._streams_lock:
            sock = self._streams.get(stream_id)
        if sock:
            try:
                sock.sendall(data)
                return True
            except OSError:
                self.close_stream(stream_id)
        return False

    def close_stream(self, stream_id: int) -> None:
        """Closes a specific local stream."""
        with self._streams_lock:
            sock = self._streams.pop(stream_id, None)
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        with self._streams_lock:
            for s in list(self._streams.values()):
                try:
                    s.close()
                except OSError:
                    pass
            self._streams.clear()
