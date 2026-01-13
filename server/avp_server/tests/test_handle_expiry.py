"""Tests for capability handle expiration enforcement (AVP-003)."""
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from fastapi import HTTPException

# Import from session_utils which has minimal dependencies
from avp_server.session_utils import assert_valid_handle, assert_active_session


class TestAssertValidHandle:
    """Tests for assert_valid_handle function."""

    def test_valid_handle_not_expired(self):
        """Test that a handle with future expiration passes validation."""
        future_time = datetime.now(timezone.utc) + timedelta(hours=1)
        handle_row = {
            "handle": "hnd_test123",
            "expires_at": future_time
        }

        # Should not raise
        assert_valid_handle(handle_row)

    def test_expired_handle_raises_exception(self):
        """Test that an expired handle raises HTTPException with correct error."""
        past_time = datetime.now(timezone.utc) - timedelta(hours=1)
        handle_row = {
            "handle": "hnd_expired123",
            "expires_at": past_time
        }

        with pytest.raises(HTTPException) as exc_info:
            assert_valid_handle(handle_row)

        assert exc_info.value.status_code == 403
        detail = exc_info.value.detail
        assert detail["type"] == "error"
        assert detail["code"] == "capability_expired"
        assert "hnd_expired123" in detail["details"]["handle"]

    def test_handle_with_no_expiration(self):
        """Test that a handle with no expiration passes validation."""
        handle_row = {
            "handle": "hnd_noexpiry",
            "expires_at": None
        }

        # Should not raise
        assert_valid_handle(handle_row)

    def test_handle_expiring_now_is_rejected(self):
        """Test that a handle expiring exactly now is rejected."""
        # Use a time in the past by a tiny margin to ensure it's expired
        now = datetime.now(timezone.utc) - timedelta(seconds=1)
        handle_row = {
            "handle": "hnd_justnow",
            "expires_at": now
        }

        with pytest.raises(HTTPException) as exc_info:
            assert_valid_handle(handle_row)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["code"] == "capability_expired"

    def test_naive_datetime_handled(self):
        """Test that naive datetime (no timezone) is handled correctly."""
        # Naive datetime in the past (should be treated as UTC)
        past_naive = datetime.utcnow() - timedelta(hours=1)
        handle_row = {
            "handle": "hnd_naive_expired",
            "expires_at": past_naive
        }

        with pytest.raises(HTTPException) as exc_info:
            assert_valid_handle(handle_row)

        assert exc_info.value.detail["code"] == "capability_expired"

    def test_error_response_format(self):
        """Test that the error response follows AVP error envelope format."""
        past_time = datetime.now(timezone.utc) - timedelta(minutes=5)
        handle_row = {
            "handle": "hnd_format_test",
            "expires_at": past_time
        }

        with pytest.raises(HTTPException) as exc_info:
            assert_valid_handle(handle_row)

        detail = exc_info.value.detail
        # Verify AVP error envelope structure
        assert "avp_version" in detail
        assert detail["avp_version"] == "1.0"
        assert detail["type"] == "error"
        assert "code" in detail
        assert "message" in detail
        assert "details" in detail
        assert isinstance(detail["details"], dict)


class TestAssertActiveSession:
    """Tests for assert_active_session function."""

    def test_active_session_passes(self):
        """Test that an active session passes validation."""
        future_time = datetime.now(timezone.utc) + timedelta(hours=1)
        session_row = {
            "session_id": "ses_test123",
            "expires_at": future_time,
            "revoked_at": None
        }

        # Should not raise
        assert_active_session(session_row)

    def test_revoked_session_raises(self):
        """Test that a revoked session raises HTTPException."""
        future_time = datetime.now(timezone.utc) + timedelta(hours=1)
        session_row = {
            "session_id": "ses_revoked",
            "expires_at": future_time,
            "revoked_at": datetime.now(timezone.utc) - timedelta(minutes=5)
        }

        with pytest.raises(HTTPException) as exc_info:
            assert_active_session(session_row)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["code"] == "session_revoked"

    def test_expired_session_raises(self):
        """Test that an expired session raises HTTPException."""
        past_time = datetime.now(timezone.utc) - timedelta(hours=1)
        session_row = {
            "session_id": "ses_expired",
            "expires_at": past_time,
            "revoked_at": None
        }

        with pytest.raises(HTTPException) as exc_info:
            assert_active_session(session_row)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail["code"] == "session_expired"

