import pytest
from xmastunnel.protocol.frame import FrameType
from xmastunnel.session.session import TunnelSession, SessionSecurityError, ReplayAttackError
from xmastunnel.session.session_manager import SessionManager


def test_handshake_flow_success():
    psk = "11" * 32
    session_id = 0xABCDEF1234567890

    client_sess = TunnelSession(session_id, role="client", psk=psk)
    server_sess = TunnelSession(session_id, role="server", psk=psk)

    # 1. Client Init
    init_frame = client_sess.create_handshake_init()
    assert init_frame.frame_type == FrameType.HANDSHAKE_INIT

    # 2. Server Resp
    resp_frame = server_sess.handle_handshake_init(init_frame)
    assert resp_frame.frame_type == FrameType.HANDSHAKE_RESP

    # 3. Client Auth
    auth_frame = client_sess.handle_handshake_resp(resp_frame)
    assert auth_frame.frame_type == FrameType.HANDSHAKE_AUTH

    # 4. Server Confirm
    confirm_frame = server_sess.handle_handshake_auth(auth_frame)
    assert confirm_frame.frame_type == FrameType.HANDSHAKE_CONFIRM

    # 5. Client Confirm Verification
    client_sess.handle_handshake_confirm(confirm_frame)

    assert client_sess.is_established is True
    assert server_sess.is_established is True


def test_handshake_bad_psk_failure():
    server_psk = "11" * 32
    client_bad_psk = "22" * 32
    session_id = 9999

    client_sess = TunnelSession(session_id, role="client", psk=client_bad_psk)
    server_sess = TunnelSession(session_id, role="server", psk=server_psk)

    init_frame = client_sess.create_handshake_init()
    resp_frame = server_sess.handle_handshake_init(init_frame)
    auth_frame = client_sess.handle_handshake_resp(resp_frame)

    # Server must reject wrong PSK
    with pytest.raises(SessionSecurityError):
        server_sess.handle_handshake_auth(auth_frame)


def test_session_data_encryption_and_anti_replay():
    psk = "aa" * 32
    sid = 12345
    client = TunnelSession(sid, role="client", psk=psk)
    server = TunnelSession(sid, role="server", psk=psk)

    # Handshake
    f1 = client.create_handshake_init()
    f2 = server.handle_handshake_init(f1)
    f3 = client.handle_handshake_resp(f2)
    f4 = server.handle_handshake_auth(f3)
    client.handle_handshake_confirm(f4)

    # Client encrypts DATA
    plaintext = b"Super confidential payload"
    enc_frame = client.encrypt_frame(FrameType.DATA, plaintext)
    assert enc_frame.seq == 1

    # Server decrypts DATA
    decrypted = server.decrypt_frame(enc_frame)
    assert decrypted == plaintext

    # Replay attack: Server rejects duplicate frame with same sequence
    with pytest.raises(ReplayAttackError):
        server.decrypt_frame(enc_frame)


def test_session_manager():
    mgr = SessionManager(max_sessions=2, idle_timeout=1.0)
    s1 = mgr.create_session("server", "psk1", 100)
    s2 = mgr.create_session("server", "psk2", 200)

    assert mgr.active_session_count() == 2

    # Exceeding limit raises error
    with pytest.raises(RuntimeError):
        mgr.create_session("server", "psk3")

    mgr.remove_session(100)
    assert mgr.active_session_count() == 1
    assert mgr.get_session(100) is None
    assert mgr.get_session(200) is not None
