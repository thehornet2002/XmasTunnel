import enum
from typing import Dict, Set


class ProtocolState(enum.Enum):
    DISCONNECTED = "DISCONNECTED"
    HANDSHAKE_INIT_SENT = "HANDSHAKE_INIT_SENT"     # Client sent INIT
    HANDSHAKE_WAIT_INIT = "HANDSHAKE_WAIT_INIT"     # Server waiting for INIT
    HANDSHAKE_AUTH_SENT = "HANDSHAKE_AUTH_SENT"     # Client sent AUTH
    HANDSHAKE_WAIT_AUTH = "HANDSHAKE_WAIT_AUTH"     # Server waiting for AUTH
    ESTABLISHED = "ESTABLISHED"                     # Secure communication active
    REKEYING = "REKEYING"                           # Rekey in progress
    TERMINATING = "TERMINATING"                     # Teardown in progress
    CLOSED = "CLOSED"                               # Session completed/closed
    ERROR = "ERROR"                                 # Unrecoverable error state


class StateTransitionError(Exception):
    pass


class ProtocolStateMachine:
    """
    Manages protocol state transitions independently of TCP transport flags.
    """

    TRANSITIONS: Dict[ProtocolState, Set[ProtocolState]] = {
        ProtocolState.DISCONNECTED: {
            ProtocolState.HANDSHAKE_INIT_SENT,
            ProtocolState.HANDSHAKE_WAIT_INIT,
            ProtocolState.HANDSHAKE_WAIT_AUTH,
            ProtocolState.CLOSED,
            ProtocolState.ERROR,
        },
        ProtocolState.HANDSHAKE_WAIT_INIT: {
            ProtocolState.HANDSHAKE_WAIT_AUTH,
            ProtocolState.CLOSED,
            ProtocolState.ERROR,
        },
        ProtocolState.HANDSHAKE_INIT_SENT: {
            ProtocolState.HANDSHAKE_AUTH_SENT,
            ProtocolState.CLOSED,
            ProtocolState.ERROR,
        },
        ProtocolState.HANDSHAKE_WAIT_AUTH: {
            ProtocolState.ESTABLISHED,
            ProtocolState.CLOSED,
            ProtocolState.ERROR,
        },
        ProtocolState.HANDSHAKE_AUTH_SENT: {
            ProtocolState.ESTABLISHED,
            ProtocolState.CLOSED,
            ProtocolState.ERROR,
        },
        ProtocolState.ESTABLISHED: {
            ProtocolState.REKEYING,
            ProtocolState.TERMINATING,
            ProtocolState.CLOSED,
            ProtocolState.ERROR,
        },
        ProtocolState.REKEYING: {
            ProtocolState.ESTABLISHED,
            ProtocolState.TERMINATING,
            ProtocolState.CLOSED,
            ProtocolState.ERROR,
        },
        ProtocolState.TERMINATING: {
            ProtocolState.CLOSED,
            ProtocolState.ERROR,
        },
        ProtocolState.CLOSED: {
            ProtocolState.DISCONNECTED,
        },
        ProtocolState.ERROR: {
            ProtocolState.CLOSED,
            ProtocolState.DISCONNECTED,
        },
    }

    def __init__(self, initial_state: ProtocolState = ProtocolState.DISCONNECTED):
        self._state = initial_state

    @property
    def state(self) -> ProtocolState:
        return self._state

    def is_established(self) -> bool:
        return self._state in (ProtocolState.ESTABLISHED, ProtocolState.REKEYING)

    def transition_to(self, new_state: ProtocolState) -> None:
        allowed = self.TRANSITIONS.get(self._state, set())
        if new_state not in allowed:
            raise StateTransitionError(
                f"Invalid state transition from {self._state.value} to {new_state.value}"
            )
        self._state = new_state

    def reset(self) -> None:
        self._state = ProtocolState.DISCONNECTED
