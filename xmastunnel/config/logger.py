import logging
import re
import sys
from typing import Optional


class SensitiveDataFilter(logging.Filter):
    """
    Prevents pre-shared keys, hex secrets, and auth tokens from being logged in plaintext.
    """
    PATTERNS = [
        re.compile(r"([0-9a-fA-F]{64})"),            # 256-bit hex keys
        re.compile(r"(psk\s*=\s*['\"][^'\"]+['\"])", re.IGNORECASE),
        re.compile(r"(password\s*=\s*['\"][^'\"]+['\"])", re.IGNORECASE),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            msg = record.msg
            for pattern in self.PATTERNS:
                msg = pattern.sub(r"***REDACTED_SECRET***", msg)
            record.msg = msg
        return True


def setup_logger(
    name: str = "XmasTunnel",
    level: int = logging.INFO,
    log_file: Optional[str] = None,
) -> logging.Logger:
    """Configures application logger with sensitive data sanitization."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid duplicate handlers on re-init
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(SensitiveDataFilter())
    logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        file_handler.addFilter(SensitiveDataFilter())
        logger.addHandler(file_handler)

    return logger
