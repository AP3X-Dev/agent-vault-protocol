"""Secret selection utilities with label binding.

This module contains the secret selection logic that can be tested
without heavy database dependencies.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Tuple

from .config import settings


def select_secret(
    fetchone_fn: Callable,
    conn: Any,
    principal_id: int,
    service: str,
    environment: str,
    resource: Optional[str],
    allow_fallback: Optional[bool] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Select secret by service, environment, and label (resource).
    
    AVP-010: When resource is present, it maps to the secret's label field.
    AVP-011: If resource is None and allow_label_fallback is False, returns error.
    
    Args:
        fetchone_fn: Function to fetch one row from database (for testability)
        conn: Database connection
        principal_id: Principal ID
        service: Service name (e.g., "openai")
        environment: Environment (e.g., "prod", "dev")
        resource: Resource label from capability (maps to secrets.label)
        allow_fallback: Override settings.allow_label_fallback (for testing)
    
    Returns:
        Tuple of (secret_row, error_message). If error_message is set, secret_row is None.
    """
    # Use passed-in value or fall back to settings
    fallback_allowed = allow_fallback if allow_fallback is not None else settings.allow_label_fallback
    
    if resource is not None:
        # Select by exact label match
        secret = fetchone_fn(conn, """
            SELECT s.id
            FROM secrets s
            WHERE s.principal_id = %s 
              AND s.service_name = %s 
              AND s.environment = %s 
              AND s.label = %s
              AND s.deleted_at IS NULL
            LIMIT 1
        """, [principal_id, service, environment, resource])
        
        if not secret:
            return None, f"no secret with label '{resource}' for {service} in {environment}"
        return secret, None
    
    # No resource/label specified
    if not fallback_allowed:
        # Strict mode: require label
        return None, f"capability missing resource label for {service}; set resource to select specific secret"
    
    # Fallback mode: select newest by service+env
    secret = fetchone_fn(conn, """
        SELECT s.id
        FROM secrets s
        WHERE s.principal_id = %s 
          AND s.service_name = %s 
          AND s.environment = %s 
          AND s.deleted_at IS NULL
        ORDER BY s.updated_at DESC
        LIMIT 1
    """, [principal_id, service, environment])
    
    if not secret:
        return None, f"no secret stored for {service} in {environment}"
    return secret, None

