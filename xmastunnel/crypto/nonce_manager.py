import struct
from typing import Set, Tuple


class NonceManager:
    """
    Manages 96-bit (12-byte) nonces for AES-256-GCM.
    Structure: [4 bytes salt / IV prefix] + [8 bytes monotonic counter (uint64)]
    """
    MAX_SEQUENCE = 0xFFFFFFFFFFFFFFFF  # 2^64 - 1
    REKEY_THRESHOLD = 0x100000000      # 2^32 frames recommended rekey limit

    def __init__(self, iv_salt: bytes, initial_counter: int = 1):
        if len(iv_salt) != 4:
            raise ValueError(f"iv_salt must be 4 bytes, got {len(iv_salt)}")
        self._iv_salt = iv_salt
        self._counter = initial_counter

    @property
    def current_counter(self) -> int:
        return self._counter

    def next_nonce(self) -> Tuple[bytes, int]:
        if self._counter >= self.MAX_SEQUENCE:
            raise OverflowError("Nonce sequence counter exhausted; session rekey required immediately.")
        seq = self._counter
        nonce = self._iv_salt + struct.pack(">Q", seq)
        self._counter += 1
        return nonce, seq

    def build_nonce(self, seq: int) -> bytes:
        return self._iv_salt + struct.pack(">Q", seq)

    def should_rekey(self) -> bool:
        return self._counter >= self.REKEY_THRESHOLD

    def update_salt(self, new_salt: bytes) -> None:
        if len(new_salt) != 4:
            raise ValueError("new_salt must be 4 bytes")
        self._iv_salt = new_salt
        self._counter = 1


class ReplayProtectionWindow:
    """
    Sliding window replay protection (RFC 6479 / IPsec style).
    Window size: 64 packets. Rejects past duplicates or packets too old.
    """
    def __init__(self, window_size: int = 64):
        self.window_size = window_size
        self.max_seq_received = 0
        self.received_set: Set[int] = set()

    def is_valid_and_update(self, seq: int) -> bool:
        if seq <= 0:
            return False

        if seq > self.max_seq_received:
            # New highest sequence number seen
            diff = seq - self.max_seq_received
            if diff > self.window_size:
                self.received_set.clear()
            else:
                # Remove items that fell off the left of the window
                cutoff = seq - self.window_size
                self.received_set = {s for s in self.received_set if s > cutoff}
            self.max_seq_received = seq
            self.received_set.add(seq)
            return True

        # seq is <= max_seq_received
        if seq <= self.max_seq_received - self.window_size:
            # Too old, outside the sliding window
            return False

        if seq in self.received_set:
            # Replay detected!
            return False

        self.received_set.add(seq)
        return True

    def reset(self) -> None:
        self.max_seq_received = 0
        self.received_set.clear()
