# Low-Level Network Packet Engine & TCP Flags Inspection

## 1. Technical Limitation of Standard OS Sockets

A standard TCP socket (`AF_INET`, `SOCK_STREAM`) operates at the transport layer of the operating system network stack. When an application writes or reads from a stream socket:
- The OS kernel manages the TCP state machine (RFC 793 / RFC 9293).
- Flags such as `SYN`, `ACK`, `FIN`, `RST` are emitted automatically by the kernel TCP/IP driver.
- The user application **cannot** arbitrarily set flags (e.g. injecting `URG|PSH|FIN` or anomalous flag combinations) on an established socket.

Attempting to manipulate TCP flags directly on an active stream socket results in kernel interference (e.g., immediate RST or ignore).

Therefore, XmasTunnel establishes a strict architectural separation:
1. **Production Tunnel Transport**: Uses standard high-performance, non-blocking TCP sockets with `TCP_NODELAY` and `SO_KEEPALIVE`.
2. **Packet Engine Subsystem**: An isolated raw packet crafting, analysis, and injection engine designed for network diagnostics, firewall traversal analysis, and TCP flag anomaly testing.

---

## 2. Supported TCP Flags

The packet engine supports arbitrary bitmask combinations of all 8 standard and extended TCP control flags:

| Flag | Bit Value | Name | Description |
|------|-----------|------|-------------|
| `FIN` | `0x01` | Finish | No more data from sender |
| `SYN` | `0x02` | Synchronize | Synchronize sequence numbers (connection init) |
| `RST` | `0x04` | Reset | Reset the connection |
| `PSH` | `0x08` | Push | Push function (deliver data to app immediately) |
| `ACK` | `0x10` | Acknowledgment | Acknowledgment field significant |
| `URG` | `0x20` | Urgent | Urgent pointer field significant |
| `ECE` | `0x40` | ECN-Echo | Explicit Congestion Notification Echo (RFC 3168) |
| `CWR` | `0x80` | Congestion Window Reduced | Sender reduced transmission rate |

### Built-in Test Profiles:
- **`XMAS_TREE` (`FIN|URG|PSH`)**: The classic "Christmas tree" packet with all push, urgent, and fin lights turned on. Historically used to probe firewall statefulness and OS TCP stack compliance (RFC 793 indicates closed ports reply with RST, open ports drop packet).
- **`SYN_PROBE` (`SYN`)**: Simulates standard SYN connection initiation.
- **`SYN_ACK` (`SYN|ACK`)**: Simulates server SYN-ACK handshake response.
- **`NULL_FLAGS` (`NONE`)**: All flags 0; probes stack behavior against undefined TCP states.
- **`ALL_FLAGS` (`FIN|SYN|RST|PSH|ACK|URG|ECE|CWR`)**: Maximum stress probe testing firewall packet inspection rules.
- **`SYN_FIN_CONFLICT` (`SYN|FIN`)**: Contradictory connection open and close in single header.

---

## 3. Checksum Computation (RFC 1071 / RFC 793)

The packet engine includes a pure-Python implementation of the standard 16-bit One's Complement Internet Checksum algorithm:

### 3.1 IPv4 Header Checksum
Computed over the 20-byte IPv4 header with the checksum field initialized to zero.

### 3.2 TCP Checksum with Pseudo-Header
TCP requires checksum calculation over a 12-byte IPv4 pseudo-header concatenated with the TCP header and payload:
```
+--------+--------+--------+--------+
|           Source Address          | (4 bytes)
+--------+--------+--------+--------+
|         Destination Address       | (4 bytes)
+--------+--------+--------+--------+
|  Zero  |  PTCL  |    TCP Length   | (1 byte zero + 1 byte proto 6 + 2 bytes len)
+--------+--------+--------+--------+
|         TCP Header + Data         |
+--------+--------+--------+--------+
```

---

## 4. Operating System Raw Socket Capabilities & Drivers

| Technology | OS | Layer | Privileges Required | Notes |
|------------|----|-------|---------------------|-------|
| `AF_PACKET` | Linux | Layer 2 (Ethernet) | `CAP_NET_RAW` / root | Raw frame access; bypasses kernel IP stack. |
| `SOCK_RAW (IPPROTO_RAW)` | Linux | Layer 3 (IPv4) | `CAP_NET_RAW` / root | Custom IP & TCP headers. |
| `AF_XDP` | Linux | Kernel BPF / XDP | Kernel 4.18+, Root | Zero-copy high-performance packet routing. |
| `DPDK` | Linux / BSD | Userspace Driver | Dedicated NIC + Hugepages | Sub-microsecond latency, bypasses kernel. |
| `Windows Raw Sockets` | Windows | Layer 3 | Administrator | Microsoft restricted sending raw TCP via `SOCK_RAW` since Windows XP SP2 to prevent spoofing. |
| `Npcap / WinPcap` | Windows | Layer 2/3 Driver | Kernel Driver + Admin | Required for live raw packet transmission on Windows. |
| `Isolated Loopback Engine` | Cross-platform | In-Memory | None | Built-in fallback allowing 100% test coverage without drivers or root. |
