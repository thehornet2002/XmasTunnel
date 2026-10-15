import socket
import threading
import time
import pytest
from xmastunnel.config.config import ServerConfig, ClientConfig
from xmastunnel.crypto.kdf import generate_server_psk
from xmastunnel.server import TunnelServer
from xmastunnel.client import TunnelClient
from xmastunnel.protocol.frame import ProtocolError
from xmastunnel.transport.tcp_transport import TransportError


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_full_tunnel_integration_and_rekey():
    port = get_free_port()
    psk = generate_server_psk()

    server_cfg = ServerConfig(
        host="127.0.0.1",
        port=port,
        psk=psk,
        verbose=False,
    )
    server = TunnelServer(server_cfg)
    server.start(blocking=False)
    time.sleep(0.2)

    try:
        client_cfg = ClientConfig(
            remote_host="127.0.0.1",
            remote_port=port,
            psk=psk,
            timeout=5.0,
            verbose=False,
        )
        client = TunnelClient(client_cfg)
        client.connect()
        assert client.is_connected is True

        # Test 1: Ping
        rtt = client.ping()
        assert rtt >= 0.0

        # Test 2: Send encrypted data and receive echo response
        test_payload = b"TopSecretNetworkPayload12345"
        client.send_data(test_payload)
        resp = client.recv_data(timeout=5.0)
        assert resp == b"ACK:" + test_payload

        # Test 3: Rekeying
        client.rekey()
        assert client.is_connected is True

        # Test 4: Post-rekey data transfer
        post_rekey_payload = b"DataAfterKeyRotation"
        client.send_data(post_rekey_payload)
        resp2 = client.recv_data(timeout=5.0)
        assert resp2 == b"ACK:" + post_rekey_payload

        client.close()

    finally:
        server.stop()


def test_client_wrong_psk_rejected():
    port = get_free_port()
    server_psk = generate_server_psk()
    wrong_psk = generate_server_psk()

    server_cfg = ServerConfig(
        host="127.0.0.1",
        port=port,
        psk=server_psk,
    )
    server = TunnelServer(server_cfg)
    server.start(blocking=False)
    time.sleep(0.2)

    try:
        client_cfg = ClientConfig(
            remote_host="127.0.0.1",
            remote_port=port,
            psk=wrong_psk,
            timeout=3.0,
            retry_count=1,
        )
        client = TunnelClient(client_cfg)
        with pytest.raises((ProtocolError, TransportError)):
            client.connect()
    finally:
        server.stop()
