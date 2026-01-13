from __future__ import annotations

import os
from typing import Any, Dict, Optional, Sequence

import psycopg
from psycopg_pool import ConnectionPool
from psycopg.rows import dict_row

from .config import settings


_pool: Optional[ConnectionPool] = None


def get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(conninfo=settings.database_url, min_size=1, max_size=10, open=True)
    return _pool


def run_migrations() -> None:
    pool = get_pool()
    migrations_dir = os.path.join(os.path.dirname(__file__), "..", "migrations")
    migrations_dir = os.path.abspath(migrations_dir)

    sql_files = sorted([f for f in os.listdir(migrations_dir) if f.endswith(".sql")])
    if not sql_files:
        return

    with pool.connection() as conn:
        conn.execute("SELECT 1;")
        for fname in sql_files:
            path = os.path.join(migrations_dir, fname)
            with open(path, "r", encoding="utf-8") as f:
                sql = f.read()
            conn.execute(sql)
        conn.commit()


def fetchone(conn: psycopg.Connection, query: str, params: Sequence[Any] | None = None) -> Optional[Dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(query, params or [])
        row = cur.fetchone()
        return dict(row) if row else None


def fetchall(conn: psycopg.Connection, query: str, params: Sequence[Any] | None = None) -> list[Dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(query, params or [])
        rows = cur.fetchall()
        return [dict(r) for r in rows]


def execute(conn: psycopg.Connection, query: str, params: Sequence[Any] | None = None) -> None:
    with conn.cursor() as cur:
        cur.execute(query, params or [])
