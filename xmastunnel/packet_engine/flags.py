import enum
from typing import Dict, List, Set, Union


class TCPFlag(enum.IntFlag):
    """TCP Header Control Flags (RFC 793, RFC 3168)."""
    NONE = 0x00
    FIN  = 0x01
    SYN  = 0x02
    RST  = 0x04
    PSH  = 0x08
    ACK  = 0x10
    URG  = 0x20
    ECE  = 0x40  # ECN-Echo
    CWR  = 0x80  # Congestion Window Reduced


# Famous test profiles
TEST_PROFILES: Dict[str, TCPFlag] = {
    "SYN_PROBE": TCPFlag.SYN,
    "SYN_ACK": TCPFlag.SYN | TCPFlag.ACK,
    "ACK_ONLY": TCPFlag.ACK,
    "FIN_PROBE": TCPFlag.FIN,
    "XMAS_TREE": TCPFlag.FIN | TCPFlag.URG | TCPFlag.PSH,  # Classic Christmas scan
    "NULL_FLAGS": TCPFlag.NONE,                            # No flags set
    "ALL_FLAGS": (
        TCPFlag.FIN | TCPFlag.SYN | TCPFlag.RST | TCPFlag.PSH
        | TCPFlag.ACK | TCPFlag.URG | TCPFlag.ECE | TCPFlag.CWR
    ),
    "SYN_FIN_CONFLICT": TCPFlag.SYN | TCPFlag.FIN,         # Illegal simultaneous open/close
    "RST_ACK": TCPFlag.RST | TCPFlag.ACK,
    "URG_ONLY": TCPFlag.URG,
    "ECE_CWR": TCPFlag.ECE | TCPFlag.CWR,
}


def parse_flags(flag_input: Union[int, str, List[str], TCPFlag]) -> TCPFlag:
    """
    Parses flags from integer bitmask, TCPFlag, comma-separated string, or list of names.
    Examples:
      parse_flags("SYN,ACK") -> TCPFlag.SYN | TCPFlag.ACK
      parse_flags(["FIN", "URG", "PSH"]) -> TCPFlag.FIN | TCPFlag.URG | TCPFlag.PSH
    """
    if isinstance(flag_input, TCPFlag):
        return flag_input
    if isinstance(flag_input, int):
        return TCPFlag(flag_input & 0xFF)
    if isinstance(flag_input, str):
        flag_names = [f.strip().upper() for f in flag_input.split(",") if f.strip()]
    elif isinstance(flag_input, (list, tuple, set)):
        flag_names = [str(f).strip().upper() for f in flag_input if str(f).strip()]
    else:
        raise ValueError(f"Unsupported flag input type: {type(flag_input)}")

    result = TCPFlag.NONE
    for name in flag_names:
        if name in TCPFlag.__members__:
            result |= TCPFlag.__members__[name]
        elif name in TEST_PROFILES:
            result |= TEST_PROFILES[name]
        else:
            raise ValueError(f"Unknown TCP flag or profile name: '{name}'")
    return result


def flags_to_str(flags: TCPFlag) -> str:
    """Formats active TCP flags as human-readable string (e.g. 'FIN|PSH|URG')."""
    if flags == TCPFlag.NONE:
        return "NONE"
    active = [flag.name for flag in TCPFlag if flag != TCPFlag.NONE and flag in flags]
    return "|".join(active)
