from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from .db import fetchone, execute
from .config import settings

_ph = PasswordHasher()


def token_sha256(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_token(token: str) -> str:
    return _ph.hash(token)


def verify_token(token: str, token_hash: str) -> bool:
    try:
        return _ph.verify(token_hash, token)
    except VerifyMismatchError:
        return False


def new_token(prefix: str) -> str:
    return f"{prefix}{secrets.token_urlsafe(32)}"


@dataclass(frozen=True)
class AuthContext:
    principal_id: int
    agent_db_id: Optional[int]
    token_type: str
    scopes: list[str]
    session_template: Dict[str, Any]


def authenticate_bearer(conn, bearer: str, expected_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
    sha = token_sha256(bearer)
    row = fetchone(conn, """
        SELECT id, principal_id, agent_id, token_sha256, token_hash, token_type, scopes, session_template, expires_at, revoked_at
        FROM api_tokens
        WHERE token_sha256 = %s
        """, [sha])
    if not row:
        return None
    if expected_type and row["token_type"] != expected_type:
        return None
    if row["revoked_at"] is not None:
        return None
    if row["expires_at"] is not None:
        if row["expires_at"] <= datetime.now(timezone.utc):
            return None
    if not verify_token(bearer, row["token_hash"]):
        return None
    return row


def authenticate_session(conn, bearer: str) -> Optional[Dict[str, Any]]:
    sha = token_sha256(bearer)
    row = fetchone(conn, """
        SELECT id, session_id, principal_id, agent_id, agent_logical_id, session_token_sha256, session_token_hash,
               granted_capabilities, constraints, created_at, expires_at, revoked_at, revoked_reason
        FROM sessions
        WHERE session_token_sha256 = %s
        """, [sha])
    if not row:
        return None
    if row["revoked_at"] is not None:
        return None
    if row["expires_at"] <= datetime.now(timezone.utc):
        return None
    if not verify_token(bearer, row["session_token_hash"]):
        return None
    return row
