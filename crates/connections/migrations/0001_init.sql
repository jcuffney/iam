-- Connections database (role `iam_connections`). Store-isolated from the
-- identity database: separate database, separate role with no cross-grants,
-- separate encryption key. Holds live bearer secrets (encrypted), so a leaked
-- identity-DB credential cannot reach it.
--
-- Principal ids here reference the identity database and therefore cannot be
-- foreign keys; the service layer validates them.

CREATE TABLE connections (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id       uuid NOT NULL,                       -- owner; validated against the identity DB
    org_id             uuid NOT NULL,
    provider           text NOT NULL,
    kind               text NOT NULL CHECK (kind IN ('mcp', 'api_key', 'oauth')),
    scopes_held        text[] NOT NULL DEFAULT '{}',
    secret_ciphertext  bytea NOT NULL,                      -- AES-256-GCM
    secret_nonce       bytea NOT NULL,
    refresh_ciphertext bytea,                               -- refresh token, if any
    refresh_nonce      bytea,
    refresh_status     text,
    last_refreshed_at  timestamptz,
    expires_at         timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    revoked_at         timestamptz
);
CREATE INDEX connections_principal_idx ON connections (principal_id) WHERE revoked_at IS NULL;

CREATE TABLE capabilities (
    connection_id uuid NOT NULL REFERENCES connections (id) ON DELETE CASCADE,
    operation     text NOT NULL,                            -- 'mcp:<tool>' | 'model:<endpoint>' | '*'
    scopable      boolean NOT NULL,
    PRIMARY KEY (connection_id, operation)
);

CREATE TABLE grants (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id  uuid NOT NULL,                            -- grantee; validated against the identity DB
    granted_by    uuid NOT NULL,
    connection_id uuid NOT NULL REFERENCES connections (id) ON DELETE CASCADE,
    operation     text NOT NULL,
    constraints   jsonb NOT NULL DEFAULT '[]',              -- serialized Vec<Constraint>
    expires_at    timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    revoked_at    timestamptz
);
CREATE INDEX grants_lookup_idx ON grants (principal_id, connection_id, operation) WHERE revoked_at IS NULL;
