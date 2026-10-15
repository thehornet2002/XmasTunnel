# XmasTunnel Architecture Specification

## 1. Architectural Overview

XmasTunnel is a modular, high-security TCP tunneling software engineered to deliver authenticated, confidential data transmission with low-level TCP packet analysis capabilities.

The software strictly decouples **transport stream reliability** from **cryptographic state** and **low-level packet inspection**.

```
+-------------------------------------------------------------------------+
|                              Application                                |
|          CLI / Tunnel Client                     Tunnel Server          |
+-------------------------------------------------------------------------+
       |                                                 |
       v                                                 v
+-------------------------------------------------------------------------+
|                            Session Manager                              |
|   - Session Lifecycle (Create, Query, Re-key, Teardown)                 |
|   - Concurrency bounds & Inactive session expiration                    |
|   - Session ID mappings (64-bit entropy)                                |
+-------------------------------------------------------------------------+
       |                                                 |
       v                                                 v
+-------------------------------------------------------------------------+
|                        Protocol & State Machine                         |
|   - Binary Framing (Magic: XT, Version, Type, Seq, Payload Len)         |
|   - Independent Protocol State Machine (INIT -> AUTH -> ESTABLISHED)   |
|   - Stream Buffer Reassembly & Chunk Parser                             |
+-------------------------------------------------------------------------+
       |                                                 |
       v                                                 v
+-------------------------------------------------------------------------+
|                           Cryptography Layer                            |
|   - Authenticated Encryption: AES-256-GCM (128-bit authentication tag)  |
|   - Key Derivation: HKDF-SHA256 (high entropy) / PBKDF2 (passphrase)    |
|   - Directional Session Keys (Client-to-Server vs Server-to-Client)     |
|   - Nonce Isolation: 96-bit (4-byte IV salt + 8-byte monotonic counter) |
|   - Anti-Replay: 64-bit sliding window protection                       |
+-------------------------------------------------------------------------+
       |                                                 |
       v                                                 v
+-------------------------------------------------------------------------+
|                             Transport Layer                             |
|   - Standard OS TCP Stream Socket (AF_INET, SOCK_STREAM)                |
|   - TCP_NODELAY (Nagle disabled) & SO_KEEPALIVE                         |
|   - Token-bucket Rate Limiter & Socket Timeout Management               |
+-------------------------------------------------------------------------+

======================== INDEPENDENT SUBSYSTEM ============================

+-------------------------------------------------------------------------+
|                     Packet Engine (Low-Level Testing)                   |
|   - Raw Packet Crafter: IPv4 + TCP Header Serialization                 |
|   - Flags Engine: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR bitmasks       |
|   - Checksum Engine: RFC 1071 Internet Checksum + IPv4 Pseudo-Header    |
|   - OS Detection: Linux CAP_NET_RAW / Windows Npcap limitation check    |
|   - In-Memory Loopback / Test Injection Harness                         |
+-------------------------------------------------------------------------+
```

---

## 2. Component Decoupling & Isolation

### 2.1 Cryptography vs Transport
The cryptographic layer operates on discrete frames and does not assume packet boundaries correspond to socket read boundaries. Frame headers are authenticated as **Additional Authenticated Data (AAD)** inside AES-256-GCM, preventing header tampering, length manipulation, or sequence number spoofing.

### 2.2 Protocol State Machine vs TCP Flags
In standard socket programming, TCP flags (`SYN`, `ACK`, `FIN`, `RST`) are strictly owned by the operating system kernel. The internal protocol maintains its own state machine (`HANDSHAKE_INIT_SENT`, `HANDSHAKE_WAIT_AUTH`, `ESTABLISHED`, `REKEYING`, `TERMINATING`, `CLOSED`) over the TCP byte stream. Transport interruptions or normal TCP segmentation do not alter the cryptographic or logical state of the tunnel.

### 2.3 Packet Engine vs Live Tunnel
The `PacketEngine` is isolated from the live encrypted data stream. It allows security researchers, network engineers, and QA to craft, validate, and inject arbitrary TCP flag combinations (such as Christmas tree packets: `FIN|URG|PSH`, NULL scans, or SYN probes) without disrupting the running tunnel transport.
