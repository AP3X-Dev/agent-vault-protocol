<div align="center">
  <img src=".github/images/avp_header.png" alt="Agent Vault Protocol" width="800"/>
</div>

# Agent Vault Protocol (AVP)

This repo contains a working MVP reference implementation of AVP v1.0.

What is included

1. FastAPI server implementing control plane and AVP data plane
2. Postgres schema migration
3. AES GCM encrypted secret storage with versioning
4. Argon2 token hashing for principal, agent, and session tokens
5. Capability intersection and session enforcement
6. Secret resolution bundles (environment and json)
7. Proxy calls for OpenAI Chat Completions (proxy only mode)
8. CLI to replace .env workflows
9. Python SDK (bootstrap helper)
10. Example agent script

## Quickstart (Docker)

1. Copy env file and edit as needed

```bash
cp .env.example .env
```

2. Start Postgres and the server

```bash
docker compose up --build
```

3. Bootstrap a principal (dev mode only)

```bash
python -m cli.avp_cli.main init --url http://localhost:8000 --email you@example.com --name "You"
```

4. Add an OpenAI secret

```bash
python -m cli.avp_cli.main add-secret --service openai --label personal_default --environment prod --api-key sk_your_key
```

5. Create an agent and agent token

```bash
python -m cli.avp_cli.main create-agent --agent-id deep_researcher --name "Deep Researcher"
python -m cli.avp_cli.main create-agent-token --agent-id deep_researcher
```

6. Run an example script without a .env file

```bash
python -m cli.avp_cli.main run --agent-id deep_researcher -- python examples/langgraph/main.py
```

## Notes

Security model

This MVP uses a local DEK derived from AVP_DEK_B64 for encrypting secrets. In production you should wrap the DEK using a real KMS. The code is structured so you can replace the local key provider.

Proxy calls

Proxy calls are implemented for OpenAI Chat Completions using the stored OpenAI API key. The agent never receives the key in proxy only mode.

## Repo layout

- server/avp_server: FastAPI server
- server/migrations: SQL migration files
- cli/avp_cli: CLI tool
- sdk-python/avp_client: Python SDK
- examples/langgraph: simple example script
