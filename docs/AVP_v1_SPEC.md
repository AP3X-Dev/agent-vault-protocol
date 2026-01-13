# AVP v1.0 (MVP reference)

This document describes what the code in this repo implements.

Actors

- Principal: owner of a vault, controls secrets and agent policies
- Agent: a client process that requests capabilities and then resolves secrets or uses proxy calls
- Vault: the AVP server, stores encrypted secrets and issues scoped sessions

Tokens

- Principal token: bearer token used for control plane endpoints
- Agent token: bearer token tied to a single agent under a principal
- Session token: short lived bearer token issued during agent_hello

Capability

A capability is a tuple:

- service
- scopes (subset)
- environment
- optional resource
- mode: secret_resolution, proxy_only, or both

Flow

1. Principal creates agent and agent token
2. Agent calls /avp/agent_hello with requested capabilities
3. Vault intersects requested capabilities with the agent token session template
4. Vault issues a session and returns a session token plus capability handles for proxy calls
5. Agent calls /avp/resolve_secrets to receive a secret bundle (if allowed)
6. Agent calls /avp/proxy_call to perform a remote operation (if allowed)

MVP constraints

- Secrets are encrypted using AES GCM with a local DEK from AVP_DEK_B64
- Only OpenAI chat proxy is implemented
- Secret selection chooses the newest secret for a service and environment
