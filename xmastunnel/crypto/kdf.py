import os
import secrets
from typing import Dict, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_server_psk() -> str:
    """Generate a cryptographically secure 256-bit pre-shared key (64 hex characters)."""
    return secrets.token_hex(32)


def is_high_entropy_psk(psk: str) -> bool:
    """Check if PSK looks like a 64-char hexadecimal high-entropy key."""
    if len(psk) == 64:
        try:
            bytes.fromhex(psk)
            return True
        except ValueError:
            return False
    return False


def derive_master_key(psk: str, salt: bytes) -> bytes:
    """
    Derive 256-bit master key.
    Uses direct bytes if 64-char hex, otherwise runs PBKDF2-HMAC-SHA256 (300,000 iterations).
    """
    if is_high_entropy_psk(psk):
        # Already 256 bits of high entropy, extract using HKDF-Extract directly
        raw_key = bytes.fromhex(psk)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"XmasTunnel-Master-Extraction",
        )
        return hkdf.derive(raw_key)
    else:
        # Human passphrase: use PBKDF2 with high iteration count against offline guessing
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=300_000,
        )
        return kdf.derive(psk.encode("utf-8"))


def derive_session_keys(
    master_key: bytes,
    salt: bytes,
    client_random: bytes,
    server_random: bytes,
) -> Dict[str, bytes]:
    """
    Derive directional keys and IV prefixes using HKDF.
    Returns:
      - c2s_key: 32 bytes (Client-to-Server AES-256 key)
      - s2c_key: 32 bytes (Server-to-Client AES-256 key)
      - c2s_salt: 4 bytes (Client IV prefix)
      - s2c_salt: 4 bytes (Server IV prefix)
    """
    context = client_random + server_random
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32 + 32 + 4 + 4,  # 72 bytes total
        salt=salt,
        info=b"XmasTunnel-Session-Keys-v1|" + context,
    )
    derived = hkdf.derive(master_key)
    c2s_key = derived[0:32]
    s2c_key = derived[32:64]
    c2s_salt = derived[64:68]
    s2c_salt = derived[68:72]

    return {
        "c2s_key": c2s_key,
        "s2c_key": s2c_key,
        "c2s_salt": c2s_salt,
        "s2c_salt": s2c_salt,
    }


def derive_rekey(
    current_key: bytes,
    rekey_nonce: bytes,
    direction: str,
) -> Tuple[bytes, bytes]:
    """
    Derive a new 32-byte key and 4-byte IV salt for key rotation.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=36,
        salt=rekey_nonce,
        info=f"XmasTunnel-Rekey-{direction}".encode("ascii"),
    )
    out = hkdf.derive(current_key)
    return out[0:32], out[32:36]
