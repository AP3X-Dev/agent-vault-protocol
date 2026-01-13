from __future__ import annotations

from typing import Any, Dict, Optional
import json

from .db import execute


def audit_event(
    conn,
    *,
    principal_id: Optional[int],
    agent_db_id: Optional[int],
    session_db_id: Optional[int],
    session_id: Optional[str],
    event_type: str,
    service_name: Optional[str] = None,
    capability: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    execute(conn, """
        INSERT INTO audit_logs (
            principal_id, agent_id, session_db_id, session_id, event_type, service_name, capability::jsonb,
            request_id, ip_address, user_agent, metadata::jsonb
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s
        )
    """, [
        principal_id,
        agent_db_id,
        session_db_id,
        session_id,
        event_type,
        service_name,
        capability,
        request_id,
        ip_address,
        user_agent,
        metadata or {},
    ])
