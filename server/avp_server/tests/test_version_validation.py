"""Tests for AVP version validation (AVP-021)."""
import pytest
from pydantic import ValidationError

from avp_server.models import (
    AgentHello,
    ResolveSecrets,
    ProxyCall,
    SessionRevoke,
    Capability,
    StrictAVPModel,
)


class TestVersionValidation:
    """Tests for avp_version field validation."""
    
    def test_valid_version_accepted(self):
        """Test that version 1.0 is accepted."""
        msg = AgentHello(
            avp_version="1.0",
            agent_id="test-agent",
            requested_capabilities=[]
        )
        assert msg.avp_version == "1.0"
    
    def test_invalid_version_rejected(self):
        """Test that invalid versions are rejected."""
        with pytest.raises(ValidationError) as exc_info:
            AgentHello(
                avp_version="2.0",  # Invalid version
                agent_id="test-agent",
                requested_capabilities=[]
            )
        
        errors = exc_info.value.errors()
        assert any("avp_version" in str(e) for e in errors)
    
    def test_missing_version_uses_default(self):
        """Test that missing version defaults to 1.0."""
        msg = AgentHello(
            agent_id="test-agent",
            requested_capabilities=[]
        )
        assert msg.avp_version == "1.0"


class TestExtraFieldsRejected:
    """Tests for rejecting unknown fields (security measure)."""
    
    def test_extra_field_in_agent_hello_rejected(self):
        """Test that extra fields in AgentHello are rejected."""
        with pytest.raises(ValidationError) as exc_info:
            AgentHello(
                avp_version="1.0",
                agent_id="test-agent",
                requested_capabilities=[],
                malicious_field="injected"  # Extra field
            )
        
        errors = exc_info.value.errors()
        assert any("extra" in str(e).lower() or "malicious_field" in str(e) for e in errors)
    
    def test_extra_field_in_capability_rejected(self):
        """Test that extra fields in Capability are rejected."""
        with pytest.raises(ValidationError) as exc_info:
            Capability(
                service="openai",
                scopes=["chat"],
                environment="prod",
                extra_scope="admin"  # Extra field
            )
        
        errors = exc_info.value.errors()
        assert len(errors) > 0
    
    def test_extra_field_in_proxy_call_rejected(self):
        """Test that extra fields in ProxyCall are rejected."""
        with pytest.raises(ValidationError) as exc_info:
            ProxyCall(
                avp_version="1.0",
                session_id="ses_123",
                capability_handle="hnd_123",
                operation="chat",
                hidden_param="secret"  # Extra field
            )
        
        errors = exc_info.value.errors()
        assert len(errors) > 0
    
    def test_extra_field_in_resolve_secrets_rejected(self):
        """Test that extra fields in ResolveSecrets are rejected."""
        with pytest.raises(ValidationError) as exc_info:
            ResolveSecrets(
                avp_version="1.0",
                session_id="ses_123",
                inject_service="attacker"  # Extra field
            )
        
        errors = exc_info.value.errors()
        assert len(errors) > 0


class TestTypeValidation:
    """Tests for message type field validation."""
    
    def test_type_field_correct_for_agent_hello(self):
        """Test that AgentHello has correct type."""
        msg = AgentHello(
            agent_id="test",
            requested_capabilities=[]
        )
        assert msg.type == "agent_hello"
    
    def test_type_field_correct_for_resolve_secrets(self):
        """Test that ResolveSecrets has correct type."""
        msg = ResolveSecrets(session_id="ses_123")
        assert msg.type == "resolve_secrets"
    
    def test_type_field_correct_for_proxy_call(self):
        """Test that ProxyCall has correct type."""
        msg = ProxyCall(
            session_id="ses_123",
            capability_handle="hnd_123",
            operation="chat"
        )
        assert msg.type == "proxy_call"


class TestStrictAVPModelBase:
    """Tests for the StrictAVPModel base class."""
    
    def test_strict_model_forbids_extra(self):
        """Test that StrictAVPModel forbids extra fields."""
        class TestModel(StrictAVPModel):
            field1: str
        
        with pytest.raises(ValidationError):
            TestModel(field1="value", extra="not_allowed")
    
    def test_strict_model_allows_valid_fields(self):
        """Test that StrictAVPModel allows valid fields."""
        class TestModel(StrictAVPModel):
            field1: str
            field2: int = 0
        
        model = TestModel(field1="value")
        assert model.field1 == "value"
        assert model.field2 == 0

