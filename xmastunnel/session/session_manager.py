import secrets
import threading
import time
from typing import Dict, List, Optional
from .session import TunnelSession


class SessionManager:
    """
    Manages active tunnel sessions, timeouts, concurrency limits and lifecycle.
    """

    def __init__(self, max_sessions: int = 100, idle_timeout: float = 300.0):
        self.max_sessions = max_sessions
        self.idle_timeout = idle_timeout
        self._sessions: Dict[int, TunnelSession] = {}
        self._lock = threading.Lock()

    def generate_session_id(self) -> int:
        """Generate a random 64-bit session ID."""
        while True:
            # 63-bit positive uint64
            sid = secrets.randbits(63)
            if sid != 0 and sid not in self._sessions:
                return sid

    def create_session(
        self,
        role: str,
        psk: str,
        session_id: Optional[int] = None,
    ) -> TunnelSession:
        with self._lock:
            self._cleanup_idle_locked()
            if len(self._sessions) >= self.max_sessions:
                raise RuntimeError(f"Session limit reached ({self.max_sessions})")

            sid = session_id if session_id is not None else self.generate_session_id()
            session = TunnelSession(session_id=sid, role=role, psk=psk)
            self._sessions[sid] = session
            return session

    def get_session(self, session_id: int) -> Optional[TunnelSession]:
        with self._lock:
            return self._sessions.get(session_id)

    def remove_session(self, session_id: int) -> Optional[TunnelSession]:
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if session:
                session.close()
            return session

    def active_session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def list_sessions(self) -> List[dict]:
        with self._lock:
            now = time.time()
            return [
                {
                    "session_id": sid,
                    "role": s.role,
                    "state": s.state.value,
                    "bytes_sent": s.bytes_sent,
                    "bytes_received": s.bytes_received,
                    "idle_seconds": round(now - s.last_active_at, 2),
                }
                for sid, s in self._sessions.items()
            ]

    def cleanup_idle(self) -> int:
        with self._lock:
            return self._cleanup_idle_locked()

    def _cleanup_idle_locked(self) -> int:
        now = time.time()
        expired = [
            sid
            for sid, s in self._sessions.items()
            if (now - s.last_active_at) > self.idle_timeout
        ]
        for sid in expired:
            s = self._sessions.pop(sid)
            s.close()
        return len(expired)
