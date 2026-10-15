import logging
import queue
import socket
import struct
import threading
import time
from typing import Optional, Tuple
from ..protocol.frame import Frame, FrameParser
from ..packet_engine.flags import parse_flags, flags_to_str
from .tcp_transport import TransportError, ConnectionClosedError, ConnectionTimeoutError


def flags_to_scapy(flags_input) -> str:
    """Converts flag profile names or strings into Scapy flag characters."""
    s = str(flags_input).upper()
    if s == "XMAS_TREE":
        return "FPU"
    if s == "ALL_FLAGS":
        return "FSRPAUEC"
    if s == "SYN_ACK":
        return "SA"
    if s == "RST_ACK":
        return "RA"
    if s == "NONE":
        return ""
    
    mapping = {
        "FIN": "F",
        "SYN": "S",
        "RST": "R",
        "PSH": "P",
        "ACK": "A",
        "URG": "U",
        "ECE": "E",
        "CWR": "C",
    }
    res = "".join(v for k, v in mapping.items() if k in s)
    return res if res else "FPU"


class RawTunnelConnection:
    """
    Encapsulates a Layer 3/4 Raw Packet Tunnel Connection.
    Every frame is sent directly with exact user-configured TCP flags (FIN|PSH|URG / Xmas),
    completely bypassing the operating system's automatic TCP state machine.
    """

    def __init__(
        self,
        local_ip: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        tx_flags: str = "XMAS_TREE",
        timeout: float = 30.0,
        start_sniffer: bool = True,
        logger: Optional[logging.Logger] = None,
    ):
        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.tx_flags_name = tx_flags
        self.scapy_flags = flags_to_scapy(tx_flags)
        self.timeout = timeout
        self.logger = logger or logging.getLogger("XmasTunnel.RawTransport")

        self.parser = FrameParser()
        self._frame_queue: queue.Queue[Frame] = queue.Queue()
        self._closed = False
        self._seq = 1000
        self._seq_lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._sniffer = None
        self._l3_sock = None

        try:
            from scapy.all import conf
            self._l3_sock = conf.L3socket()
        except Exception as e:
            self.logger.debug(f"Persistent L3 socket notice: {e}")

        if start_sniffer:
            from scapy.all import AsyncSniffer, TCP, IP, Raw
            bpf_filter = f"tcp and dst port {self.local_port}"
            if self.remote_ip and self.remote_ip != "0.0.0.0" and self.remote_ip != "ANY":
                bpf_filter = f"tcp and src host {self.remote_ip} and dst port {self.local_port}"

            def _on_packet(pkt):
                if Raw in pkt and TCP in pkt:
                    self.feed_raw_packet(pkt[Raw].load)

            try:
                self._sniffer = AsyncSniffer(filter=bpf_filter, prn=_on_packet, store=False)
                self._sniffer.start()
                self.logger.info(
                    f"[RawTransport] Sniffer active for dst port {self.local_port} (TX Flags: {self.tx_flags_name})"
                )
            except Exception as e:
                self.logger.warning(f"[RawTransport] Could not start packet sniffer: {e}")
                self._sniffer = None

    def feed_raw_packet(self, data: bytes) -> None:
        """Feeds raw payload bytes into the parser and queues assembly frames."""
        self.parser.feed(data)
        while True:
            f = self.parser.next_frame()
            if f is None:
                break
            self._frame_queue.put(f)

    @property
    def peer_address(self) -> Tuple[str, int]:
        return (self.remote_ip, self.remote_port)

    @property
    def local_address(self) -> Tuple[str, int]:
        return (self.local_ip, self.local_port)

    def send_frame(self, frame: Frame) -> None:
        """Packs frame into a Raw TCP Packet with custom flags and transmits it."""
        with self._send_lock:
            if self._closed:
                raise TransportError("Cannot send on closed raw connection")

            from scapy.all import IP, TCP, Raw

            data = frame.pack()
            with self._seq_lock:
                seq_val = self._seq
                self._seq = (self._seq + len(data)) & 0xFFFFFFFF

            pkt = (
                IP(dst=self.remote_ip)
                / TCP(
                    sport=self.local_port,
                    dport=self.remote_port,
                    flags=self.scapy_flags,
                    seq=seq_val,
                )
                / Raw(load=data)
            )

            try:
                if self._l3_sock:
                    self._l3_sock.send(pkt)
                else:
                    from scapy.all import send
                    send(pkt, verbose=False)
            except Exception as e:
                raise TransportError(f"Failed to transmit raw packet: {e}") from e

    def recv_frame(self, timeout: Optional[float] = None) -> Optional[Frame]:
        """Waits for next complete frame from sniffer queue."""
        if self._closed:
            return None

        eff_timeout = timeout if timeout is not None else self.timeout
        try:
            return self._frame_queue.get(timeout=eff_timeout)
        except queue.Empty:
            raise ConnectionTimeoutError("Raw packet recv timed out")

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            if self._sniffer:
                try:
                    self._sniffer.stop()
                except Exception:
                    pass
            if self._l3_sock:
                try:
                    self._l3_sock.close()
                except Exception:
                    pass
            self.logger.info("[RawTransport] Raw connection closed.")
