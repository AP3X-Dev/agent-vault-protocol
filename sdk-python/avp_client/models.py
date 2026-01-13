from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class SessionInfo:
    session_id: str
    session_token: str
    expires_at: str
    granted_capabilities: List[Dict[str, Any]]
    capability_handles: Dict[str, str]
