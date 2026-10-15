import socket
import struct
import threading
import time
import pytest
from xmastunnel.config.config import ServerConfig, ClientConfig
from xmastunnel.crypto.kdf import generate_server_psk
from xmastunnel.server import TunnelServer
from xmastunnel.client import TunnelClient


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_socks5_proxy_over_xmastunnel():
    # 1. Setup target echo server (simulating internet destination)
    target_port = get_free_port()
    target_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    target_server.bind(("127.0.0.1", target_port))
    target_server.listen(5)

    target_running = True

    def echo_worker():
        while target_running:
            try:
                sock, _ = target_server.accept()
                while True:
                    data = sock.recv(1024)
                    if not data:
                        break
                    sock.sendall(b"ECHO:" + data)
                sock.close()
            except OSError:
                break

    t_echo = threading.Thread(target=echo_worker, daemon=True)
    t_echo.start()

    # 2. Setup XmasTunnel Server
    tunnel_port = get_free_port()
    psk = generate_server_psk()

    server_cfg = ServerConfig(
        host="127.0.0.1",
        port=tunnel_port,
        psk=psk,
    )
    server = TunnelServer(server_cfg)
    server.start(blocking=False)
    time.sleep(0.2)

    # 3. Setup XmasTunnel Client and SOCKS5 Proxy
    socks_port = get_free_port()
    client_cfg = ClientConfig(
        remote_host="127.0.0.1",
        remote_port=tunnel_port,
        psk=psk,
    )
    client = TunnelClient(client_cfg)
    client.connect()
    assert client.is_connected is True

    client.start_socks_proxy(listen_host="127.0.0.1", listen_port=socks_port)
    time.sleep(0.3)

    # 4. Connect via SOCKS5 client socket
    socks_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks_sock.connect(("127.0.0.1", socks_port))

    # Greeting
    socks_sock.sendall(b"\x05\x01\x00")
    greet_resp = socks_sock.recv(2)
    assert greet_resp == b"\x05\x00"

    # CONNECT request to 127.0.0.1:target_port
    dest_ip_bytes = socket.inet_aton("127.0.0.1")
    req = b"\x05\x01\x00\x01" + dest_ip_bytes + struct.pack(">H", target_port)
    socks_sock.sendall(req)

    conn_resp = socks_sock.recv(10)
    assert len(conn_resp) == 10
    assert conn_resp[0] == 0x05
    assert conn_resp[1] == 0x00  # SUCCESS

    # Send data through SOCKS5 proxy over encrypted tunnel
    payload = b"HelloViaEncryptedTunnelSocks5"
    socks_sock.sendall(payload)

    reply = socks_sock.recv(1024)
    assert reply == b"ECHO:" + payload

    # Teardown
    socks_sock.close()
    client.close()
    server.stop()
    target_running = False
    target_server.close()
