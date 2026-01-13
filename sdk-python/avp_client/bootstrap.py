from __future__ import annotations

import os
from typing import Any, Dict, Optional

from .client import AVPClient


def avp_bootstrap(
    *,
    agent_id: str,
    requested_capabilities: list[dict],
    agent_token_env: str = "AVP_AGENT_TOKEN",
    install_env: bool = True,
) -> Dict[str, Any]:
    """Bootstrap secrets for an agent.

    Steps:
    1. agent_hello with requested capabilities
    2. resolve_secrets environment format
    3. optionally install into os.environ

    Returns a dict with session info and resolved secrets.
    """
    agent_token = os.environ.get(agent_token_env)
    if not agent_token:
        raise RuntimeError(f"missing {agent_token_env}")

    client = AVPClient.from_env()
    sess = client.agent_hello(agent_token=agent_token, agent_id=agent_id, requested_capabilities=requested_capabilities)
    secrets_map = client.resolve_secrets(session_token=sess.session_token, session_id=sess.session_id, format="environment")

    if install_env:
        client.install_env(secrets_map)

    return {
        "session_id": sess.session_id,
        "session_token": sess.session_token,
        "expires_at": sess.expires_at,
        "secrets": secrets_map,
        "capability_handles": sess.capability_handles,
    }
