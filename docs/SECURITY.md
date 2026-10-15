# XmasTunnel Security Architecture & Threat Model

## 1. Threat Model & Security Objectives

XmasTunnel is designed against an active adversary capable of sniffing, modifying, replaying, injecting, and dropping packets along the network route (Dolev-Yao threat model).

| Threat | Defense Mechanism | Invariant Guaranteed |
|--------|-------------------|----------------------|
| **Eavesdropping / Packet Sniffing** | AES-256-GCM authenticated encryption | Confidentiality ($2^{256}$ security level) |
| **Payload Tampering / Bit-flipping** | 128-bit Poly1305/GHASH GCM Authentication Tag | Integrity & Authenticity |
| **Header / Framing Tampering** | 24-byte Frame Header bound into AAD | Complete frame metadata authenticity |
| **Replay Attacks** | 64-frame sliding window + monotonic sequence counter | Replays rejected immediately |
| **Nonce Reuse Catastrophe** | 4-byte static IV salt + 8-byte monotonic counter per direction | Unique nonces per frame guaranteed |
| **Offline Dictionary Attacks** | 300,000-iteration PBKDF2-HMAC-SHA256 for passphrases | High computational cost per guess |
| **Known-Key Impersonation** | Ephemeral `client_random` + `server_random` in HKDF derivation | Forward secrecy across sessions |
| **Log Leakage / Shoulder Surfing** | `SensitiveDataFilter` regex redactor in logging subsystem | Zero plaintext keys or secrets in logs |

---

## 2. Nonce Management Invariants

In AES-GCM, reusing a `(Key, Nonce)` pair allows an attacker to recover the authentication key ($H$) and forge messages.
XmasTunnel enforces two independent mechanisms to guarantee nonce uniqueness:
1. **Directional Separation**: The client and server have distinct directional keys and 4-byte IV prefixes (`c2s_salt` and `s2c_salt`). Even if sequence numbers coincide, nonces and keys differ.
2. **Strict Monotonic Increment**: Every frame transmitted increments a 64-bit unsigned integer counter. Nonce values never repeat within a session key lifespan.

---

## 3. Pre-Shared Key (PSK) Lifecycle

- **Server Auto-Generation**: When started without `--key`, the server uses `secrets.token_hex(32)` to generate a 256-bit cryptographically random key.
- **Hex Entropy Check**: If the provided key is 64 hex characters, HKDF extracts entropy directly. If an arbitrary string is supplied, PBKDF2-HMAC-SHA256 (300,000 iterations) is executed to resist offline brute-force attacks.
- **Secure Memory**: Keys are encapsulated in class instances and never exposed in error tracebacks or exception messages.
