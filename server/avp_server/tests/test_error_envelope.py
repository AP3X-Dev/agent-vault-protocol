"""Tests for AVP error envelope format (AVP-020)."""
import pytest
from unittest.mock import MagicMock, patch

from avp_server.error_utils import (
    generate_correlation_id as _generate_correlation_id,
    avp_error_response as _avp_error_response,
    ERROR_CODES,
)


class TestCorrelationId:
    """Tests for correlation ID generation."""
    
    def test_correlation_id_format(self):
        """Test that correlation IDs have expected format."""
        cid = _generate_correlation_id()
        assert cid.startswith("err_")
        assert len(cid) > 10
    
    def test_correlation_ids_are_unique(self):
        """Test that each correlation ID is unique."""
        ids = [_generate_correlation_id() for _ in range(100)]
        assert len(set(ids)) == 100


class TestAVPErrorResponse:
    """Tests for AVP error response format."""
    
    def test_error_response_structure(self):
        """Test that error response has required fields."""
        resp = _avp_error_response("test_error", "test message")
        
        assert resp["avp_version"] == "1.0"
        assert resp["type"] == "error"
        assert resp["code"] == "test_error"
        assert resp["message"] == "test message"
        assert "details" in resp
    
    def test_error_response_with_details(self):
        """Test that details are included properly."""
        details = {"field": "value", "count": 42}
        resp = _avp_error_response("test_error", "test message", details=details)
        
        assert resp["details"]["field"] == "value"
        assert resp["details"]["count"] == 42
    
    def test_error_response_with_correlation_id(self):
        """Test that correlation ID is added to details."""
        resp = _avp_error_response("test_error", "test message", correlation_id="err_abc123")
        
        assert resp["details"]["correlation_id"] == "err_abc123"
    
    def test_error_response_correlation_id_with_existing_details(self):
        """Test that correlation ID is merged with existing details."""
        details = {"existing": "value"}
        resp = _avp_error_response("test_error", "test message", details=details, correlation_id="err_xyz")
        
        assert resp["details"]["existing"] == "value"
        assert resp["details"]["correlation_id"] == "err_xyz"


class TestErrorCodes:
    """Tests for standardized error codes."""

    def test_common_error_codes(self):
        """Document expected error codes in AVP v1.0."""
        # These are the standard error codes that should be used
        standard_codes = [
            "validation_error",      # Request validation failed
            "internal_error",        # Unexpected server error
            "http_error",            # Generic HTTP error
            "capability_denied",     # Capability not granted
            "capability_expired",    # Handle has expired
            "session_expired",       # Session has expired
            "session_revoked",       # Session was revoked
            "secret_not_found",      # No matching secret
            "operation_not_allowed", # Operation not permitted by scopes
            "rate_limit_exceeded",   # Too many requests
            "unknown_service",       # Service not in registry
            "invalid_request",       # Malformed request
        ]

        # Verify all standard codes are in ERROR_CODES
        for code in standard_codes:
            assert code in ERROR_CODES, f"Missing standard code: {code}"
        assert len(standard_codes) > 0


class TestErrorEnvelopeFormat:
    """Tests for AVP error envelope compliance."""
    
    def test_error_envelope_required_fields(self):
        """Test that all required fields are present."""
        resp = _avp_error_response("code", "message")
        
        required_fields = ["avp_version", "type", "code", "message", "details"]
        for field in required_fields:
            assert field in resp, f"Missing required field: {field}"
    
    def test_error_envelope_type_is_error(self):
        """Test that type is always 'error'."""
        resp = _avp_error_response("any_code", "any message")
        assert resp["type"] == "error"
    
    def test_error_envelope_version_is_1_0(self):
        """Test that avp_version is 1.0."""
        resp = _avp_error_response("any_code", "any message")
        assert resp["avp_version"] == "1.0"
    
    def test_details_is_always_dict(self):
        """Test that details is always a dictionary."""
        resp1 = _avp_error_response("code", "msg")
        resp2 = _avp_error_response("code", "msg", details=None)
        
        assert isinstance(resp1["details"], dict)
        assert isinstance(resp2["details"], dict)

