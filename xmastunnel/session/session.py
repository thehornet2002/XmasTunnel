import hmac
import hashlib
import secrets
import threading
import time
from typing import Optional, Tuple
from ..crypto.aes_gcm import AES256GCMCipher, CryptoError, DecryptionFailedError
from ..crypto.kdf import (
    derive_master_key,
    derive_session_keys,
    derive_rekey,
)
from ..crypto.nonce_manager import NonceManager, ReplayProtectionWindow
from ..protocol.frame import Frame, FrameType, ProtocolError
from ..protocol.state_machine import ProtocolState, ProtocolStateMachine, StateTransitionError


class SessionSecurityError(CryptoError):
    pass


class ReplayAttackError(SessionSecurityError):
    pass


class TunnelSession:
    """
    Encapsulates a secure encrypted tunnel session between client and server.
    """

    def __init__(
        self,
        session_id: int,
        role: str,  # "server" or "client"
        psk: str,
        max_bytes_before_rekey: int = 1024 * 1024 * 1024,  # 1 GB default
    ):
        if role not in ("server", "client"):
            raise ValueError(f"Invalid role: {role}")
        self.session_id = session_id
        self.role = role
        self.psk = psk
        self.max_bytes_before_rekey = max_bytes_before_rekey
        init_state = (
            ProtocolState.HANDSHAKE_WAIT_INIT if role == "server" else ProtocolState.DISCONNECTED
        )
        self.sm = ProtocolStateMachine(init_state)

        # Ephemeral handshake values
        self.client_random: bytes = b""
        self.server_random: bytes = b""
        self.salt: bytes = b""
        self.auth_challenge: bytes = b""

        # Ciphers and Nonce Managers
        self.cipher_send: Optional[AES256GCMCipher] = None
        self.cipher_recv: Optional[AES256GCMCipher] = None
        self.send_nonce_mgr: Optional[NonceManager] = None
        self.recv_nonce_mgr: Optional[NonceManager] = None
        self.replay_window = ReplayProtectionWindow(window_size=64)
        self._encrypt_lock = threading.Lock()

        # Statistics
        self.created_at = time.time()
        self.last_active_at = time.time()
        self.bytes_sent = 0
        self.bytes_received = 0
        self.frames_sent = 0
        self.frames_received = 0

    @property
    def state(self) -> ProtocolState:
        return self.sm.state

    @property
    def is_established(self) -> bool:
        return self.sm.is_established()

    # --- Handshake Phase 1: Client Init ---
    def create_handshake_init(self) -> Frame:
        """Client initiates handshake."""
        if self.role != "client":
            raise ProtocolError("Only client can initiate handshake")
        self.client_random = secrets.token_bytes(32)
        self.sm.transition_to(ProtocolState.HANDSHAKE_INIT_SENT)
        # Payload: client_random (32 bytes)
        return Frame(
            frame_type=FrameType.HANDSHAKE_INIT,
            session_id=self.session_id,
            seq=0,
            payload=self.client_random,
        )

    def handle_handshake_init(self, frame: Frame) -> Frame:
        """Server processes handshake init and replies with challenge."""
        if self.role != "server":
            raise ProtocolError("Only server can handle handshake init")
        if len(frame.payload) != 32:
            raise ProtocolError("Invalid client_random size in HANDSHAKE_INIT")

        self.client_random = frame.payload
        self.server_random = secrets.token_bytes(32)
        self.salt = secrets.token_bytes(16)
        self.auth_challenge = secrets.token_bytes(16)

        self.sm.transition_to(ProtocolState.HANDSHAKE_WAIT_AUTH)

        # Payload: server_random(32) + salt(16) + auth_challenge(16) = 64 bytes
        payload = self.server_random + self.salt + self.auth_challenge
        return Frame(
            frame_type=FrameType.HANDSHAKE_RESP,
            session_id=self.session_id,
            seq=0,
            payload=payload,
        )

    # --- Handshake Phase 2: Client Auth ---
    def handle_handshake_resp(self, frame: Frame) -> Frame:
        """Client handles server response, derives keys, and creates auth challenge response."""
        if self.role != "client":
            raise ProtocolError("Only client can handle handshake resp")
        if len(frame.payload) != 64:
            raise ProtocolError(f"Invalid HANDSHAKE_RESP length: {len(frame.payload)}")

        self.server_random = frame.payload[0:32]
        self.salt = frame.payload[32:48]
        self.auth_challenge = frame.payload[48:64]

        # Derive master key and directional session keys
        master_key = derive_master_key(self.psk, self.salt)
        keys = derive_session_keys(
            master_key, self.salt, self.client_random, self.server_random
        )

        # In client: send uses c2s, recv uses s2c
        self.cipher_send = AES256GCMCipher(keys["c2s_key"])
        self.cipher_recv = AES256GCMCipher(keys["s2c_key"])
        self.send_nonce_mgr = NonceManager(keys["c2s_salt"])
        self.recv_nonce_mgr = NonceManager(keys["s2c_salt"])

        # Compute HMAC proof over challenge
        auth_tag = hmac.new(
            master_key,
            b"XmasTunnel-ClientAuth|" + self.auth_challenge + self.client_random + self.server_random,
            hashlib.sha256,
        ).digest()

        self.sm.transition_to(ProtocolState.HANDSHAKE_AUTH_SENT)

        return Frame(
            frame_type=FrameType.HANDSHAKE_AUTH,
            session_id=self.session_id,
            seq=0,
            payload=auth_tag,
        )

    def handle_handshake_auth(self, frame: Frame) -> Frame:
        """Server verifies client auth and confirms handshake completion."""
        if self.role != "server":
            raise ProtocolError("Only server can handle handshake auth")
        if len(frame.payload) != 32:
            raise SessionSecurityError("Invalid auth tag length in HANDSHAKE_AUTH")

        master_key = derive_master_key(self.psk, self.salt)
        expected_tag = hmac.new(
            master_key,
            b"XmasTunnel-ClientAuth|" + self.auth_challenge + self.client_random + self.server_random,
            hashlib.sha256,
        ).digest()

        if not hmac.compare_digest(frame.payload, expected_tag):
            self.sm.transition_to(ProtocolState.ERROR)
            raise SessionSecurityError("Authentication failed: invalid pre-shared key or tampered challenge")

        # Derive directional session keys
        keys = derive_session_keys(
            master_key, self.salt, self.client_random, self.server_random
        )

        # In server: send uses s2c, recv uses c2s
        self.cipher_send = AES256GCMCipher(keys["s2c_key"])
        self.cipher_recv = AES256GCMCipher(keys["c2s_key"])
        self.send_nonce_mgr = NonceManager(keys["s2c_salt"])
        self.recv_nonce_mgr = NonceManager(keys["c2s_salt"])

        self.sm.transition_to(ProtocolState.ESTABLISHED)

        # Confirmation proof
        confirm_tag = hmac.new(
            master_key,
            b"XmasTunnel-ServerConfirm|" + self.auth_challenge + self.server_random,
            hashlib.sha256,
        ).digest()

        return Frame(
            frame_type=FrameType.HANDSHAKE_CONFIRM,
            session_id=self.session_id,
            seq=0,
            payload=confirm_tag,
        )

    def handle_handshake_confirm(self, frame: Frame) -> None:
        """Client receives confirmation and establishes session."""
        if self.role != "client":
            raise ProtocolError("Only client handles handshake confirm")
        if len(frame.payload) != 32:
            raise SessionSecurityError("Invalid confirm tag length")

        master_key = derive_master_key(self.psk, self.salt)
        expected_confirm = hmac.new(
            master_key,
            b"XmasTunnel-ServerConfirm|" + self.auth_challenge + self.server_random,
            hashlib.sha256,
        ).digest()

        if not hmac.compare_digest(frame.payload, expected_confirm):
            self.sm.transition_to(ProtocolState.ERROR)
            raise SessionSecurityError("Server confirmation failed: server proof does not match PSK")

        self.sm.transition_to(ProtocolState.ESTABLISHED)

    # --- Data Encryption & Decryption ---
    def encrypt_frame(self, frame_type: FrameType, plaintext: bytes) -> Frame:
        """
        Encrypts plaintext with AES-256-GCM using directional cipher & monotonic nonce.
        Header is packed and bound as Associated Authenticated Data (AAD).
        """
        with self._encrypt_lock:
            if not self.is_established:
                raise ProtocolError(f"Cannot encrypt frame in non-established state {self.state}")
            if not self.cipher_send or not self.send_nonce_mgr:
                raise CryptoError("Ciphers not initialized")

            nonce, seq = self.send_nonce_mgr.next_nonce()

            expected_payload_len = len(plaintext) + AES256GCMCipher.TAG_SIZE
            dummy_frame = Frame(
                frame_type=frame_type,
                session_id=self.session_id,
                seq=seq,
                payload=b"\x00" * expected_payload_len,
            )
            aad = dummy_frame.pack_header()

            ciphertext_with_tag = self.cipher_send.encrypt(nonce, plaintext, associated_data=aad)

            frame = Frame(
                frame_type=frame_type,
                session_id=self.session_id,
                seq=seq,
                payload=ciphertext_with_tag,
            )

            self.bytes_sent += len(frame.payload)
            self.frames_sent += 1
            self.last_active_at = time.time()
            return frame

    def decrypt_frame(self, frame: Frame) -> bytes:
        """
        Verifies replay window, constructs nonce, validates AAD header and decrypts payload.
        """
        if not self.is_established:
            raise ProtocolError(f"Cannot decrypt frame in state {self.state}")
        if not self.cipher_recv or not self.recv_nonce_mgr:
            raise CryptoError("Ciphers not initialized")

        # Anti-replay check
        if not self.replay_window.is_valid_and_update(frame.seq):
            raise ReplayAttackError(f"Duplicate or out-of-window sequence number detected: {frame.seq}")

        nonce = self.recv_nonce_mgr.build_nonce(frame.seq)
        aad = frame.pack_header()

        try:
            plaintext = self.cipher_recv.decrypt(nonce, frame.payload, associated_data=aad)
        except DecryptionFailedError as e:
            self.sm.transition_to(ProtocolState.ERROR)
            raise SessionSecurityError(f"Decryption failed: {e}") from e

        self.bytes_received += len(frame.payload)
        self.frames_received += 1
        self.last_active_at = time.time()
        return plaintext

    # --- Rekeying ---
    def should_rekey(self) -> bool:
        return (
            (self.send_nonce_mgr is not None and self.send_nonce_mgr.should_rekey())
            or (self.bytes_sent >= self.max_bytes_before_rekey)
        )

    def create_rekey_request(self) -> Frame:
        """Initiates key rotation."""
        self.sm.transition_to(ProtocolState.REKEYING)
        self._pending_rekey_nonce = secrets.token_bytes(16)
        # Encrypt the rekey token
        return self.encrypt_frame(FrameType.REKEY_REQUEST, self._pending_rekey_nonce)

    def handle_rekey_request(self, frame: Frame) -> Frame:
        """Processes peer's rekey request, derives new keys and replies."""
        rekey_nonce = self.decrypt_frame(frame)
        if len(rekey_nonce) != 16:
            raise ProtocolError("Invalid rekey nonce length")

        self.sm.transition_to(ProtocolState.REKEYING)

        send_dir = "c2s" if self.role == "client" else "s2c"
        recv_dir = "s2c" if self.role == "client" else "c2s"

        # Derive new keys for both directions
        new_send_key, new_send_salt = derive_rekey(
            self.cipher_send.key, rekey_nonce, send_dir
        )
        new_recv_key, new_recv_salt = derive_rekey(
            self.cipher_recv.key, rekey_nonce, recv_dir
        )

        # Send ACK using old key before switching
        ack_frame = self.encrypt_frame(FrameType.REKEY_ACK, b"REKEY_OK")

        # Now activate new keys
        self.cipher_send.rotate_key(new_send_key)
        self.send_nonce_mgr.update_salt(new_send_salt)

        self.cipher_recv.rotate_key(new_recv_key)
        self.recv_nonce_mgr.update_salt(new_recv_salt)
        self.replay_window.reset()

        self.sm.transition_to(ProtocolState.ESTABLISHED)
        return ack_frame

    def handle_rekey_ack(self, frame: Frame, rekey_nonce: Optional[bytes] = None) -> None:
        """Activates rotated keys after peer ACK."""
        payload = self.decrypt_frame(frame)
        if payload != b"REKEY_OK":
            raise ProtocolError("Unexpected payload in REKEY_ACK")

        nonce = rekey_nonce if rekey_nonce is not None else getattr(self, "_pending_rekey_nonce", b"")
        send_dir = "c2s" if self.role == "client" else "s2c"
        recv_dir = "s2c" if self.role == "client" else "c2s"

        new_send_key, new_send_salt = derive_rekey(
            self.cipher_send.key, nonce, send_dir
        )
        new_recv_key, new_recv_salt = derive_rekey(
            self.cipher_recv.key, nonce, recv_dir
        )

        self.cipher_send.rotate_key(new_send_key)
        self.send_nonce_mgr.update_salt(new_send_salt)

        self.cipher_recv.rotate_key(new_recv_key)
        self.recv_nonce_mgr.update_salt(new_recv_salt)
        self.replay_window.reset()
        self._pending_rekey_nonce = b""

        self.sm.transition_to(ProtocolState.ESTABLISHED)

    # --- Teardown ---
    def create_teardown(self) -> Frame:
        if self.is_established:
            frame = self.encrypt_frame(FrameType.TEARDOWN, b"GOODBYE")
        else:
            frame = Frame(FrameType.TEARDOWN, self.session_id, 0, b"GOODBYE")
        self.sm.transition_to(ProtocolState.TERMINATING)
        return frame

    def close(self) -> None:
        if self.sm.state != ProtocolState.CLOSED:
            try:
                self.sm.transition_to(ProtocolState.CLOSED)
            except StateTransitionError:
                self.sm.reset()
