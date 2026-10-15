import socket
import threading
import time
import pytest
from xmastunnel.protocol.frame import Frame, FrameType
from xmastunnel.transport.tcp_transport import (
    TCPConnection,
    connect_tcp,
    create_tcp_listener,
    TransportError,
    ConnectionClosedError,
)


def test_tcp_transport_streaming():
    listener = create_tcp_listener("127.0.0.1", 0)
    port = listener.getsockname()[1]

    received_frames = []

    def server_thread():
        client_sock, _ = listener.accept()
        conn = TCPConnection(client_sock)
        while True:
            f = conn.recv_frame(timeout=5.0)
            if f is None:
                break
            received_frames.append(f)
            # Send echo frame
            conn.send_frame(Frame(FrameType.DATA, f.session_id, f.seq, f.payload + b"_ECHO"))
        conn.close()
        listener.close()

    t = threading.Thread(target=server_thread, daemon=True)
    t.start()

    client_conn = connect_tcp("127.0.0.1", port)
    frame_to_send = Frame(FrameType.DATA, 999, 1, b"PayloadTest")
    client_conn.send_frame(frame_to_send)

    echo_frame = client_conn.recv_frame(timeout=5.0)
    assert echo_frame is not None
    assert echo_frame.payload == b"PayloadTest_ECHO"
    assert len(received_frames) == 1

    client_conn.close()
    t.join(timeout=2.0)
