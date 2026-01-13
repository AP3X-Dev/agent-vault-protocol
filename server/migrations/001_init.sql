-- AVP MVP schema (Postgres)

CREATE TABLE IF NOT EXISTS principals (
    id              BIGSERIAL PRIMARY KEY,
    external_id     TEXT UNIQUE,
    email           TEXT UNIQUE NOT NULL,
    display_name    TEXT,
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agents (
    id              BIGSERIAL PRIMARY KEY,
    principal_id    BIGINT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    agent_id        TEXT NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    default_policy  JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (principal_id, agent_id)
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id               BIGSERIAL PRIMARY KEY,
    principal_id     BIGINT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    agent_id         BIGINT REFERENCES agents(id) ON DELETE CASCADE,
    token_sha256     TEXT NOT NULL,
    token_hash       TEXT NOT NULL,
    token_type       TEXT NOT NULL,
    scopes           JSONB NOT NULL DEFAULT '[]'::jsonb,
    session_template JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ,
    revoked_at       TIMESTAMPTZ,
    revoked_reason   TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_api_tokens_token_sha256 ON api_tokens (token_sha256);

CREATE TABLE IF NOT EXISTS secrets (
    id              BIGSERIAL PRIMARY KEY,
    principal_id    BIGINT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    service_name    TEXT NOT NULL,
    label           TEXT NOT NULL,
    environment     TEXT NOT NULL DEFAULT 'prod',
    meta            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    UNIQUE (principal_id, service_name, label, environment)
);

CREATE TABLE IF NOT EXISTS secret_versions (
    id              BIGSERIAL PRIMARY KEY,
    secret_id       BIGINT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL,
    data_ciphertext BYTEA NOT NULL,
    key_version     TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      BIGINT REFERENCES principals(id),
    is_current      BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (secret_id, version)
);

CREATE INDEX IF NOT EXISTS idx_secret_versions_current ON secret_versions (secret_id) WHERE is_current = TRUE;

CREATE TABLE IF NOT EXISTS sessions (
    id                   BIGSERIAL PRIMARY KEY,
    session_id           TEXT NOT NULL UNIQUE,
    principal_id         BIGINT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    agent_id             BIGINT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    agent_logical_id     TEXT NOT NULL,
    session_token_sha256 TEXT NOT NULL,
    session_token_hash   TEXT NOT NULL,
    granted_capabilities JSONB NOT NULL,
    constraints          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at           TIMESTAMPTZ NOT NULL,
    revoked_at           TIMESTAMPTZ,
    revoked_reason       TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_session_token_sha256 ON sessions (session_token_sha256);

CREATE TABLE IF NOT EXISTS session_capabilities (
    id              BIGSERIAL PRIMARY KEY,
    session_id      BIGINT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    service_name    TEXT NOT NULL,
    scopes          TEXT[] NOT NULL,
    environment     TEXT NOT NULL,
    resource        TEXT,
    mode            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS capability_handles (
    id              BIGSERIAL PRIMARY KEY,
    handle          TEXT NOT NULL UNIQUE,
    session_id      BIGINT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    service_name    TEXT NOT NULL,
    scopes          TEXT[] NOT NULL,
    environment     TEXT NOT NULL,
    resource        TEXT,
    config          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    principal_id    BIGINT REFERENCES principals(id),
    agent_id        BIGINT REFERENCES agents(id),
    session_db_id   BIGINT REFERENCES sessions(id),
    session_id      TEXT,
    event_type      TEXT NOT NULL,
    service_name    TEXT,
    capability      JSONB,
    request_id      TEXT,
    ip_address      INET,
    user_agent      TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_session ON audit_logs (session_id);
