"""Session and capability handle utilities.

This module contains helper functions for session and handle validation
that can be imported without heavy database dependencies.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import HTTPException

from .models import AVPError


def _iso(dt: datetime) -> str:
    """Convert datetime to ISO format string in UTC."""
    return dt.astimezone(timezone.utc).isoformat()


def _avp_error(code: str, message: str, details: Optional[Dict[str, Any]] = None) -> AVPError:
    """Create an AVP error object."""
    return AVPError(code=code, message=message, details=details or {})


def assert_valid_handle(handle_row: Dict[str, Any]) -> None:
    """Validate that a capability handle is still valid (not expired).
    
    Args:
        handle_row: The database row for the capability handle, must contain:
            - handle: The handle string
            - expires_at: datetime or None
        
    Raises:
        HTTPException: If the handle has expired, with AVP error envelope
    """
    expires_at = handle_row.get("expires_at")
    if expires_at is not None:
        # Ensure timezone-aware comparison
        now = datetime.now(timezone.utc)
        if hasattr(expires_at, 'tzinfo') and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            raise HTTPException(
                status_code=403,
                detail=_avp_error(
                    "capability_expired",
                    "capability handle has expired",
                    {"handle": handle_row.get("handle"), "expired_at": _iso(expires_at)}
                ).model_dump()
            )


def assert_active_session(session_row: Dict[str, Any]) -> None:
    """Validate that a session is still active (not expired or revoked).
    
    Args:
        session_row: The database row for the session, must contain:
            - session_id: The session ID string
            - expires_at: datetime
            - revoked_at: datetime or None
        
    Raises:
        HTTPException: If the session is expired or revoked, with AVP error envelope
    """
    if session_row.get("revoked_at") is not None:
        raise HTTPException(
            status_code=403,
            detail=_avp_error(
                "session_revoked",
                "session has been revoked",
                {"session_id": session_row.get("session_id")}
            ).model_dump()
        )
    
    expires_at = session_row.get("expires_at")
    if expires_at is not None:
        now = datetime.now(timezone.utc)
        if hasattr(expires_at, 'tzinfo') and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            raise HTTPException(
                status_code=403,
                detail=_avp_error(
                    "session_expired",
                    "session has expired",
                    {"session_id": session_row.get("session_id"), "expired_at": _iso(expires_at)}
                ).model_dump()
            )

