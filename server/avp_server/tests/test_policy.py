from avp_server.policy import intersect_capabilities

def test_intersection_basic():
    allowed = [
        {"service": "openai", "scopes": ["chat", "embeddings"], "environment": "prod", "resource": None, "mode": "both"}
    ]
    requested = [
        {"service": "openai", "scopes": ["chat"], "environment": "prod", "resource": None, "mode": "secret_resolution"}
    ]
    granted = intersect_capabilities(requested, allowed)
    assert len(granted) == 1
    assert granted[0]["service"] == "openai"
    assert granted[0]["scopes"] == ["chat"]
    assert granted[0]["mode"] == "secret_resolution"

def test_intersection_denies_extra_scopes():
    allowed = [
        {"service": "openai", "scopes": ["chat"], "environment": "prod", "resource": None, "mode": "both"}
    ]
    requested = [
        {"service": "openai", "scopes": ["chat", "admin"], "environment": "prod", "resource": None, "mode": "both"}
    ]
    granted = intersect_capabilities(requested, allowed)
    assert granted == []

def test_resource_requires_template():
    allowed = [
        {"service": "openai", "scopes": ["chat"], "environment": "prod", "resource": None, "mode": "both"}
    ]
    requested = [
        {"service": "openai", "scopes": ["chat"], "environment": "prod", "resource": "project:1", "mode": "both"}
    ]
    granted = intersect_capabilities(requested, allowed)
    assert granted == []
