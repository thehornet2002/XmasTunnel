# XmasTunnel Protocol Specification

## 1. Frame Binary Layout

Every frame transmitted over the TCP tunnel adheres to a fixed 24-byte header followed by variable payload data:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Magic (b"XT")           |  Version (1)  |  Frame Type   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                       Session ID (64-bit)                     +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                    Sequence Number (64-bit)                   +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Payload Length                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|           Payload (Ciphertext + 16-byte GCM Tag)              |
|                     (Length bytes)                            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Field Definitions:
- **Magic (2 bytes)**: Fixed `0x58 0x54` (`ASCII "XT"`). Rejects spurious connections immediately.
- **Version (1 byte)**: Protocol version (`0x01`).
- **Frame Type (1 byte)**:
  - `0x01` (`HANDSHAKE_INIT`): Initiates connection; payload = 32-byte `client_random`.
  - `0x02` (`HANDSHAKE_RESP`): Server reply; payload = 32-byte `server_random` + 16-byte `salt` + 16-byte `auth_challenge` (64 bytes total).
  - `0x03` (`HANDSHAKE_AUTH`): Client auth proof; payload = 32-byte HMAC-SHA256 tag.
  - `0x04` (`HANDSHAKE_CONFIRM`): Server confirmation proof; payload = 32-byte HMAC-SHA256 tag.
  - `0x10` (`DATA`): Encrypted application payload.
  - `0x20` (`PING`): Encrypted keepalive request.
  - `0x21` (`PONG`): Encrypted keepalive response.
  - `0x30` (`REKEY_REQUEST`): Encrypted key rotation trigger.
  - `0x31` (`REKEY_ACK`): Encrypted key rotation acknowledgment.
  - `0xFF` (`TEARDOWN`): Controlled graceful termination.
- **Session ID (8 bytes)**: Unique 64-bit session identifier.
- **Sequence Number (8 bytes)**: Monotonically increasing sequence number (big-endian uint64).
- **Payload Length (4 bytes)**: Unsigned 32-bit integer indicating payload length (max 65,536 bytes).

---

## 2. Authenticated Encryption with Associated Data (AEAD)

For encrypted frames (`DATA`, `PING`, `PONG`, `REKEY_REQUEST`, `REKEY_ACK`):
1. **Nonce Composition**:
   ```
   [ 4 Bytes: Directional IV Salt ] + [ 8 Bytes: Monotonic uint64 Sequence Number ]
   ```
   Total Nonce Size = 12 bytes (96 bits), perfectly suited for AES-256-GCM without counter wrap risks.
2. **Associated Authenticated Data (AAD)**:
   The complete 24-byte frame header is passed as AAD into AES-GCM.
   Any tampering with `Magic`, `Version`, `FrameType`, `Session ID`, `Sequence Number`, or `Payload Length` causes GCM tag verification to fail immediately.

---

## 3. Four-Way Cryptographic Handshake

```
Client                                                   Server
  |                                                         |
  | -------- 1. HANDSHAKE_INIT (client_random) -----------> |
  |                                                         |
  | <------- 2. HANDSHAKE_RESP ---------------------------- |
  |            (server_random, salt, auth_challenge)        |
  |                                                         |
  [ Derive Master Key from PSK + Salt ]                     |
  [ Derive c2s_key, s2c_key, c2s_salt, s2c_salt ]           |
  [ Compute HMAC(MasterKey, Challenge+Randoms) ]            |
  |                                                         |
  | -------- 3. HANDSHAKE_AUTH (HMAC auth_tag) -----------> |
  |                                                         [ Verify HMAC with PSK ]
  |                                                         [ Derive directional keys ]
  |                                                         [ Compute Confirm HMAC ]
  |                                                         |
  | <------- 4. HANDSHAKE_CONFIRM (Confirm HMAC) ---------- |
  [ Verify Confirm HMAC ]                                   |
  |                                                         |
  <================= ESTABLISHED (AES-256-GCM) ============>
```

---

## 4. Key Rotation (Re-keying)

Keys are rotated either when:
- Sequence counter approaches safe limits.
- Total bytes transferred exceeds configurable threshold (default: 1 GB).
- On-demand via administrative trigger.

Both parties use HKDF-Expand with fresh 16-byte random salt to derive new directional keys and reset sequence counters without tearing down the TCP stream.
