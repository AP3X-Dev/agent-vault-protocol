"""Error handling utilities for AVP.

This module contains error handling functions that can be imported
without heavy dependencies for testing.
"""
from __future__ import annotations

import secrets
from typing import Any, Dict, Optional


def generate_correlation_id() -> str:
    """Generate a unique correlation ID for error tracking.
    
    Returns a string like 'err_abc123xyz' that can be used to correlate
    client-side errors with server-side logs.
    """
    return f"err_{secrets.token_urlsafe(12)}"


def avp_error_response(
    code: str, 
    message: str, 
    details: Optional[Dict[str, Any]] = None,
    correlation_id: Optional[str] = None
) -> Dict[str, Any]:
    """Create an AVP error envelope response.
    
    Args:
        code: Error code (e.g., "validation_error", "internal_error")
        message: Human-readable error message
        details: Additional error details
        correlation_id: Unique ID for error tracking
    
    Returns:
        Dictionary with AVP error envelope format:
        {
            "avp_version": "1.0",
            "type": "error",
            "code": "<code>",
            "message": "<message>",
            "details": {...}
        }
    """
    response = {
        "avp_version": "1.0",
        "type": "error",
        "code": code,
        "message": message,
        "details": details.copy() if details else {}
    }
    if correlation_id:
        response["details"]["correlation_id"] = correlation_id
    return response


# Standard AVP error codes
ERROR_CODES = {
    "validation_error": "Request validation failed",
    "internal_error": "Unexpected server error",
    "http_error": "Generic HTTP error",
    "capability_denied": "Capability not granted",
    "capability_expired": "Handle has expired",
    "session_expired": "Session has expired",
    "session_revoked": "Session was revoked",
    "secret_not_found": "No matching secret",
    "operation_not_allowed": "Operation not permitted by scopes",
    "rate_limit_exceeded": "Too many requests",
    "unknown_service": "Service not in registry",
    "invalid_request": "Malformed request",
}

