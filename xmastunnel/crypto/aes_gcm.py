from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class CryptoError(Exception):
    """Base exception for cryptographic failures."""
    pass


class DecryptionFailedError(CryptoError):
    """Raised when ciphertext or authentication tag fails verification."""
    pass


class AES256GCMCipher:
    """
    AES-256-GCM Authenticated Encryption with Associated Data (AEAD).
    Key size: 256 bits (32 bytes).
    Authentication tag: 128 bits (16 bytes).
    Nonce size: 96 bits (12 bytes).
    """

    KEY_SIZE = 32
    NONCE_SIZE = 12
    TAG_SIZE = 16

    def __init__(self, key: bytes):
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"AES-256 key must be exactly {self.KEY_SIZE} bytes, got {len(key)}")
        self._key = key
        self._cipher = AESGCM(self._key)

    @property
    def key(self) -> bytes:
        return self._key

    def rotate_key(self, new_key: bytes) -> None:
        if len(new_key) != self.KEY_SIZE:
            raise ValueError(f"New AES-256 key must be {self.KEY_SIZE} bytes, got {len(new_key)}")
        self._key = new_key
        self._cipher = AESGCM(self._key)

    def encrypt(
        self,
        nonce: bytes,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Encrypts plaintext with AES-256-GCM.
        Returns ciphertext concatenated with 16-byte authentication tag.
        """
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(f"Nonce must be {self.NONCE_SIZE} bytes, got {len(nonce)}")
        return self._cipher.encrypt(nonce, plaintext, associated_data)

    def decrypt(
        self,
        nonce: bytes,
        ciphertext_with_tag: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypts ciphertext and verifies authentication tag against associated data.
        Raises DecryptionFailedError on tampering or tag mismatch.
        """
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(f"Nonce must be {self.NONCE_SIZE} bytes, got {len(nonce)}")
        if len(ciphertext_with_tag) < self.TAG_SIZE:
            raise DecryptionFailedError(
                f"Ciphertext too short: minimum {self.TAG_SIZE} bytes required for tag, got {len(ciphertext_with_tag)}"
            )

        try:
            return self._cipher.decrypt(nonce, ciphertext_with_tag, associated_data)
        except InvalidTag as e:
            raise DecryptionFailedError("Authentication tag mismatch: data tampered or corrupted") from e
