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
