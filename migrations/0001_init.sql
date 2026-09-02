-- Identity database (role `iam`). Holds the durable identity tree: orgs,
-- principals, credentials, roles, role assignments, one-time codes, and the
-- append-only audit trail. Public keys and hashes only — no bearer secrets
-- (those live in the separately-credentialed iam_connections database).

CREATE TABLE orgs (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        text NOT NULL UNIQUE,
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE principals (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    kind         text NOT NULL CHECK (kind IN ('human', 'device', 'agent')),
    handle       text NOT NULL,
    display_name text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    disabled_at  timestamptz,
    UNIQUE (org_id, handle),
    -- Composite-unique so principal_roles can enforce same-org membership.
    UNIQUE (id, org_id)
);

CREATE TABLE credentials (
    credential_id bytea PRIMARY KEY,                        -- raw WebAuthn credential ID
    principal_id  uuid NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
    kind          text NOT NULL CHECK (kind IN ('passkey')),-- 'wallet' will join later
    passkey_data  bytea NOT NULL,                           -- serialized webauthn-rs Passkey; verification source of truth
    sign_count    bigint NOT NULL DEFAULT 0,                -- mirrored u32; regression => possible clone
    transports    text[] NOT NULL DEFAULT '{}',
    aaguid        uuid,                                     -- NULL in the none-attestation passkey flow
    nickname      text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);
CREATE INDEX credentials_principal_idx ON credentials (principal_id);

CREATE TABLE roles (
    id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id  uuid NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    name    text NOT NULL,
    UNIQUE (org_id, name),
    UNIQUE (id, org_id)
);

CREATE TABLE role_permissions (
    role_id    uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission text NOT NULL,                               -- canonical Permission string; unknown => load error
    PRIMARY KEY (role_id, permission)
);

CREATE TABLE principal_roles (
    org_id       uuid NOT NULL,
    principal_id uuid NOT NULL,
    role_id      uuid NOT NULL,
    granted_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_id, role_id),
    -- Composite FKs force the principal and the role into the same org: a
    -- principal can never hold a role from another tenant.
    FOREIGN KEY (principal_id, org_id) REFERENCES principals (id, org_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id, org_id)      REFERENCES roles (id, org_id) ON DELETE CASCADE
);

CREATE TABLE one_time_codes (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id uuid NOT NULL REFERENCES principals (id) ON DELETE CASCADE,
    purpose      text NOT NULL CHECK (purpose IN ('recovery', 'registration')),
    code_hash    text NOT NULL,                             -- argon2id PHC string
    created_at   timestamptz NOT NULL DEFAULT now(),
    used_at      timestamptz
);
CREATE INDEX one_time_codes_live_idx ON one_time_codes (principal_id, purpose) WHERE used_at IS NULL;

CREATE TABLE audit_events (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES orgs (id),
    actor_id     uuid NOT NULL REFERENCES principals (id),
    asserted_id  uuid REFERENCES principals (id),
    action       text NOT NULL,                             -- permission string, capability ref, or lifecycle action
    decision     text NOT NULL CHECK (decision IN ('allow', 'deny')),
    assurance    text CHECK (assurance IN ('asserted', 'cryptographic')),
    reason       text,
    ip           text,                                      -- textual form; avoids the sqlx inet feature
    occurred_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_org_time_idx   ON audit_events (org_id, occurred_at DESC);
CREATE INDEX audit_actor_time_idx ON audit_events (actor_id, occurred_at DESC);

-- Append-only, enforced in the database and not merely by the trait shape.
CREATE FUNCTION forbid_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS
$$ BEGIN RAISE EXCEPTION 'audit_events is append-only'; END $$;

CREATE TRIGGER audit_append_only
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION forbid_audit_mutation();
