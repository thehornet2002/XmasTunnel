import os
import pytest
from xmastunnel.crypto.aes_gcm import AES256GCMCipher, DecryptionFailedError
from xmastunnel.crypto.kdf import (
    generate_server_psk,
    derive_master_key,
    derive_session_keys,
    derive_rekey,
    is_high_entropy_psk,
)
from xmastunnel.crypto.nonce_manager import NonceManager, ReplayProtectionWindow


def test_aes_gcm_encrypt_decrypt_roundtrip():
    key = os.urandom(32)
    cipher = AES256GCMCipher(key)
    nonce = os.urandom(12)
    plaintext = b"Confidential tunnel payload with AES-256-GCM"
    aad = b"HeaderAssociatedData"

    ciphertext = cipher.encrypt(nonce, plaintext, associated_data=aad)
    assert len(ciphertext) == len(plaintext) + 16  # 16-byte authentication tag

    decrypted = cipher.decrypt(nonce, ciphertext, associated_data=aad)
    assert decrypted == plaintext


def test_aes_gcm_tamper_detection():
    key = os.urandom(32)
    cipher = AES256GCMCipher(key)
    nonce = os.urandom(12)
    plaintext = b"Sensitive message"
    aad = b"HeaderAssociatedData"

    ciphertext = cipher.encrypt(nonce, plaintext, associated_data=aad)

    # Tamper with ciphertext
    tampered_ct = bytearray(ciphertext)
    tampered_ct[0] ^= 0x01
    with pytest.raises(DecryptionFailedError):
        cipher.decrypt(nonce, bytes(tampered_ct), associated_data=aad)

    # Tamper with AAD
    with pytest.raises(DecryptionFailedError):
        cipher.decrypt(nonce, ciphertext, associated_data=b"TamperedAAD")

    # Tamper with Nonce
    tampered_nonce = bytearray(nonce)
    tampered_nonce[0] ^= 0x01
    with pytest.raises(DecryptionFailedError):
        cipher.decrypt(bytes(tampered_nonce), ciphertext, associated_data=aad)


def test_psk_generation_and_detection():
    psk = generate_server_psk()
    assert len(psk) == 64
    assert is_high_entropy_psk(psk) is True
    assert is_high_entropy_psk("short-passphrase") is False


def test_kdf_derivation_deterministic():
    psk = "0" * 64
    salt = b"A" * 16
    client_random = b"C" * 32
    server_random = b"S" * 32

    master1 = derive_master_key(psk, salt)
    master2 = derive_master_key(psk, salt)
    assert master1 == master2
    assert len(master1) == 32

    keys1 = derive_session_keys(master1, salt, client_random, server_random)
    keys2 = derive_session_keys(master1, salt, client_random, server_random)
    assert keys1["c2s_key"] == keys2["c2s_key"]
    assert keys1["s2c_key"] == keys2["s2c_key"]
    assert len(keys1["c2s_key"]) == 32
    assert len(keys1["s2c_key"]) == 32
    assert len(keys1["c2s_salt"]) == 4
    assert len(keys1["s2c_salt"]) == 4


def test_nonce_manager_monotonic():
    salt = b"\x01\x02\x03\x04"
    mgr = NonceManager(salt, initial_counter=1)

    nonce1, seq1 = mgr.next_nonce()
    nonce2, seq2 = mgr.next_nonce()

    assert seq1 == 1
    assert seq2 == 2
    assert len(nonce1) == 12
    assert nonce1[:4] == salt
    assert nonce1 != nonce2


def test_replay_protection_window():
    window = ReplayProtectionWindow(window_size=64)

    # Sequence 1 to 5: valid
    for s in range(1, 6):
        assert window.is_valid_and_update(s) is True

    # Replay of sequence 3: must be rejected!
    assert window.is_valid_and_update(3) is False
    assert window.is_valid_and_update(1) is False

    # Jump ahead
    assert window.is_valid_and_update(100) is True
    # Replay of 100: rejected
    assert window.is_valid_and_update(100) is False
    # Sequence within sliding window [100 - 64 = 36]: 70 is valid once
    assert window.is_valid_and_update(70) is True
    assert window.is_valid_and_update(70) is False
    # Sequence outside window (< 36): rejected as too old
    assert window.is_valid_and_update(20) is False
