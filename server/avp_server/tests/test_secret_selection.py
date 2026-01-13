"""Tests for secret selection with label binding (AVP-010, AVP-011)."""
import pytest
from unittest.mock import MagicMock, patch

from avp_server.secret_selection import select_secret


class TestSelectSecret:
    """Tests for select_secret function."""

    def test_select_by_label_finds_matching_secret(self):
        """Test that secret is found when label matches."""
        mock_conn = MagicMock()
        mock_secret = {"id": 123}

        # Create mock fetchone that returns our secret
        def mock_fetchone(conn, query, params):
            # Verify label was used in query
            assert "my-project" in params
            return mock_secret

        secret, error = select_secret(
            mock_fetchone,
            mock_conn,
            principal_id=1,
            service="openai",
            environment="prod",
            resource="my-project"
        )

        assert secret == mock_secret
        assert error is None

    def test_select_by_label_not_found(self):
        """Test error when labeled secret doesn't exist."""
        mock_conn = MagicMock()

        def mock_fetchone(conn, query, params):
            return None

        secret, error = select_secret(
            mock_fetchone,
            mock_conn,
            principal_id=1,
            service="openai",
            environment="prod",
            resource="nonexistent-label"
        )

        assert secret is None
        assert "nonexistent-label" in error
        assert "no secret with label" in error

    def test_no_label_strict_mode_rejects(self):
        """Test that missing label is rejected in strict mode (default)."""
        mock_conn = MagicMock()

        def mock_fetchone(conn, query, params):
            return {"id": 123}

        # Use allow_fallback=False to simulate strict mode
        secret, error = select_secret(
            mock_fetchone,
            mock_conn,
            principal_id=1,
            service="openai",
            environment="prod",
            resource=None,  # No label
            allow_fallback=False
        )

        assert secret is None
        assert "missing resource label" in error

    def test_no_label_fallback_mode_selects_newest(self):
        """Test that missing label falls back to newest in fallback mode."""
        mock_conn = MagicMock()
        mock_secret = {"id": 456}

        def mock_fetchone(conn, query, params):
            return mock_secret

        secret, error = select_secret(
            mock_fetchone,
            mock_conn,
            principal_id=1,
            service="openai",
            environment="prod",
            resource=None,  # No label
            allow_fallback=True  # Fallback allowed
        )

        assert secret == mock_secret
        assert error is None

    def test_no_label_fallback_mode_no_secret_found(self):
        """Test error when no secrets exist even in fallback mode."""
        mock_conn = MagicMock()

        def mock_fetchone(conn, query, params):
            return None

        secret, error = select_secret(
            mock_fetchone,
            mock_conn,
            principal_id=1,
            service="openai",
            environment="prod",
            resource=None,
            allow_fallback=True
        )

        assert secret is None
        assert "no secret stored" in error


class TestLabelBindingInPolicy:
    """Tests for resource/label documentation in policy."""
    
    def test_policy_docstring_mentions_label_binding(self):
        """Test that intersect_capabilities docstring documents label binding."""
        from avp_server.policy import intersect_capabilities
        
        docstring = intersect_capabilities.__doc__
        assert "Label Binding" in docstring or "resource" in docstring
        assert "label" in docstring.lower()


class TestCapabilityResourceField:
    """Tests for resource field in capabilities."""
    
    def test_resource_passed_through_intersection(self):
        """Test that resource is preserved through capability intersection."""
        from avp_server.policy import intersect_capabilities
        
        allowed = [
            {"service": "openai", "scopes": ["chat"], "environment": "prod", 
             "resource": "project-alpha", "mode": "both"}
        ]
        requested = [
            {"service": "openai", "scopes": ["chat"], "environment": "prod", 
             "resource": "project-alpha", "mode": "both"}
        ]
        
        granted = intersect_capabilities(requested, allowed)
        assert len(granted) == 1
        assert granted[0]["resource"] == "project-alpha"
    
    def test_resource_mismatch_denied(self):
        """Test that mismatched resource is denied."""
        from avp_server.policy import intersect_capabilities
        
        allowed = [
            {"service": "openai", "scopes": ["chat"], "environment": "prod", 
             "resource": "project-alpha", "mode": "both"}
        ]
        requested = [
            {"service": "openai", "scopes": ["chat"], "environment": "prod", 
             "resource": "project-beta", "mode": "both"}  # Different resource
        ]
        
        granted = intersect_capabilities(requested, allowed)
        assert len(granted) == 0

