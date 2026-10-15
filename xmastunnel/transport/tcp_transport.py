import socket
import select
import threading
import time
from typing import Optional, Tuple
from ..protocol.frame import Frame, FrameParser, HEADER_SIZE, ProtocolError


class TransportError(Exception):
    """Base exception for network/socket errors."""
    pass


class ConnectionClosedError(TransportError):
    """Raised when connection was closed by peer."""
    pass


class ConnectionTimeoutError(TransportError):
    """Raised on socket timeout."""
    pass


class RateLimiter:
    """
    Token bucket rate limiter (bytes per second).
    """
    def __init__(self, rate_bytes_per_sec: int = 0):
        self.rate = rate_bytes_per_sec  # 0 = unlimited
        self.capacity = max(rate_bytes_per_sec, 65536)
        self.tokens = float(self.capacity)
        self.last_check = time.time()

    def consume(self, num_bytes: int) -> None:
        if self.rate <= 0:
            return
        now = time.time()
        elapsed = now - self.last_check
        self.last_check = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

        if self.tokens < num_bytes:
            needed = num_bytes - self.tokens
            sleep_time = needed / self.rate
            time.sleep(sleep_time)
            self.tokens = 0
            self.last_check = time.time()
        else:
            self.tokens -= num_bytes


class TCPConnection:
    """
    Encapsulates an established TCP socket connection with framing, buffering,
    timeouts, and rate limiting.
    """

    def __init__(
        self,
        sock: socket.socket,
        timeout: float = 30.0,
        rate_limit_bytes_per_sec: int = 0,
    ):
        self.sock = sock
        self.timeout = timeout
        self.rate_limiter = RateLimiter(rate_limit_bytes_per_sec)
        self.parser = FrameParser()
        self._closed = False
        self._send_lock = threading.Lock()

        # Configure socket options
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except (AttributeError, OSError):
            pass

        self.sock.settimeout(timeout)

    @property
    def peer_address(self) -> Tuple[str, int]:
        try:
            return self.sock.getpeername()
        except OSError:
            return ("0.0.0.0", 0)

    @property
    def local_address(self) -> Tuple[str, int]:
        try:
            return self.sock.getsockname()
        except OSError:
            return ("0.0.0.0", 0)

    def send_frame(self, frame: Frame) -> None:
        """Packs and transmits a complete frame over the TCP stream."""
        with self._send_lock:
            if self._closed:
                raise TransportError("Cannot send on closed connection")

            data = frame.pack()
            self.rate_limiter.consume(len(data))
            total_sent = 0
            try:
                while total_sent < len(data):
                    sent = self.sock.send(data[total_sent:])
                    if sent == 0:
                        raise ConnectionClosedError("Socket connection lost during send")
                    total_sent += sent
            except (socket.timeout, TimeoutError) as e:
                raise ConnectionTimeoutError("Send timed out") from e
            except OSError as e:
                self._closed = True
                raise TransportError(f"Socket send failed: {e}") from e

    def recv_frame(self, timeout: Optional[float] = None) -> Optional[Frame]:
        """
        Receives bytes from socket until at least one complete Frame can be parsed.
        Returns Frame, or None on graceful close.
        """
        if self._closed:
            return None

        # Check if parser already has a buffered frame ready
        buffered = self.parser.next_frame()
        if buffered is not None:
            return buffered

        effective_timeout = timeout if timeout is not None else self.timeout
        start_time = time.time()

        while not self._closed:
            remaining_time = effective_timeout - (time.time() - start_time)
            if remaining_time <= 0:
                raise ConnectionTimeoutError(f"recv_frame timed out after {effective_timeout}s")

            # Wait for data ready to read
            try:
                rlist, _, _ = select.select([self.sock], [], [], min(remaining_time, 1.0))
            except (select.error, OSError) as e:
                self._closed = True
                raise TransportError(f"Select failed: {e}") from e

            if not rlist:
                continue

            try:
                chunk = self.sock.recv(65536)
                if not chunk:
                    # EOF: connection closed by peer
                    self._closed = True
                    return None
            except (socket.timeout, TimeoutError) as e:
                raise ConnectionTimeoutError("Socket recv timed out") from e
            except OSError as e:
                self._closed = True
                raise TransportError(f"Socket recv failed: {e}") from e

            self.parser.feed(chunk)
            frame = self.parser.next_frame()
            if frame is not None:
                return frame

        return None

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass


def connect_tcp(
    host: str,
    port: int,
    timeout: float = 10.0,
    retry_count: int = 3,
    retry_delay: float = 1.0,
    rate_limit: int = 0,
) -> TCPConnection:
    """
    Connects to remote server with retries and timeout.
    """
    last_err: Optional[Exception] = None
    for attempt in range(1, retry_count + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return TCPConnection(sock, timeout=timeout, rate_limit_bytes_per_sec=rate_limit)
        except OSError as e:
            sock.close()
            last_err = e
            if attempt < retry_count:
                time.sleep(retry_delay)

    raise TransportError(
        f"Failed to connect to {host}:{port} after {retry_count} attempts: {last_err}"
    )


def create_tcp_listener(host: str, port: int, backlog: int = 128) -> socket.socket:
    """
    Binds and listens on a local TCP address.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(backlog)
    return sock
