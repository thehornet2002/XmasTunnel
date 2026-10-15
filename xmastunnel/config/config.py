import json
import os
from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8443
    psk: Optional[str] = None  # If None, automatically generated on startup
    max_sessions: int = 50
    idle_timeout: float = 300.0
    rate_limit_bytes_per_sec: int = 0  # 0 = unlimited
    server_flags: str = "SYN_ACK"      # Flags for packets emitted by server
    client_flags: str = "XMAS_TREE"    # Flags expected from client
    log_file: Optional[str] = None
    verbose: bool = False


@dataclass
class ClientConfig:
    remote_host: str = "127.0.0.1"
    remote_port: int = 8443
    psk: str = ""
    timeout: float = 15.0
    retry_count: int = 3
    retry_delay: float = 1.0
    rate_limit_bytes_per_sec: int = 0
    keepalive_interval: float = 30.0
    client_flags: str = "XMAS_TREE"    # Flags emitted by client
    server_flags: str = "SYN_ACK"      # Expected server flags
    log_file: Optional[str] = None
    verbose: bool = False


@dataclass
class PacketTestConfig:
    src_ip: str = "127.0.0.1"
    dst_ip: str = "127.0.0.1"
    src_port: int = 54321
    dst_port: int = 8443
    flags: str = "SYN,ACK"
    simulate: bool = True


def save_config(config_obj: object, file_path: str) -> None:
    data = asdict(config_obj)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_server_config(file_path: str) -> ServerConfig:
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return ServerConfig(**data)


def load_client_config(file_path: str) -> ClientConfig:
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return ClientConfig(**data)


def encode_client_token(
    server_ip: str,
    port: int,
    psk: str,
    client_flags: str = "XMAS_TREE",
    server_flags: str = "SYN_ACK",
    client_ip: str = "",
    flags: Optional[str] = None,
) -> str:
    """Encodes server connection parameters and directional flags into a portable xmas:// token."""
    import base64
    c_flags = flags if flags else client_flags
    payload = {
        "server": server_ip,
        "port": port,
        "psk": psk,
        "client_flags": c_flags,
        "server_flags": server_flags,
        "flags": c_flags,  # backward compatibility
        "client_ip": client_ip,
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"xmas://{b64}"


def decode_client_token(token: str) -> dict:
    """Decodes a portable xmas:// token into configuration parameters."""
    import base64
    cleaned = token.strip()
    if cleaned.startswith("xmas://"):
        cleaned = cleaned[len("xmas://"):]
    pad = len(cleaned) % 4
    if pad != 0:
        cleaned += "=" * (4 - pad)
    raw = base64.urlsafe_b64decode(cleaned.encode("ascii"))
    data = json.loads(raw.decode("utf-8"))
    if "client_flags" not in data and "flags" in data:
        data["client_flags"] = data["flags"]
    if "server_flags" not in data:
        data["server_flags"] = "SYN_ACK"
    return data
