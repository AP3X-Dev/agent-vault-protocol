from __future__ import annotations

from typing import Optional

from fastapi import Depends, Header, HTTPException, Request
from psycopg_pool import ConnectionPool

from .db import get_pool
from .auth import authenticate_bearer, authenticate_session


def get_conn():
    pool = get_pool()
    with pool.connection() as conn:
        yield conn


def _get_bearer(auth_header: Optional[str]) -> str:
    if not auth_header:
        raise HTTPException(status_code=401, detail="missing Authorization header")
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="invalid Authorization header")
    return parts[1]


def require_principal(request: Request, authorization: Optional[str] = Header(default=None), conn=Depends(get_conn)):
    token = _get_bearer(authorization)
    row = authenticate_bearer(conn, token, expected_type="principal")
    if not row:
        raise HTTPException(status_code=401, detail="invalid principal token")
    request.state.principal_token_row = row
    return row


def require_agent(request: Request, authorization: Optional[str] = Header(default=None), conn=Depends(get_conn)):
    token = _get_bearer(authorization)
    row = authenticate_bearer(conn, token, expected_type="agent")
    if not row:
        raise HTTPException(status_code=401, detail="invalid agent token")
    request.state.agent_token_row = row
    return row


def require_session(request: Request, authorization: Optional[str] = Header(default=None), conn=Depends(get_conn)):
    token = _get_bearer(authorization)
    row = authenticate_session(conn, token)
    if not row:
        raise HTTPException(status_code=401, detail="invalid or expired session token")
    request.state.session_row = row
    return row
