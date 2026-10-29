"""Phase 6 hook. In phases 1-5 this is a stub.

hunter.finalize and watchdog will call login() through this single function.
"""

from __future__ import annotations


def login(session_cfg: object | None = None) -> bool:
    """Replay the portal login request. Stub: always returns False."""
    return False