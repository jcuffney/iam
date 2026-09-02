-- Least-privilege runtime role.
--
-- Migrations run as the owner (`iam`); the service serves as `iam_app`, a
-- non-owner role created in compose/init-databases.sql. `iam_app` may read and
-- write the mutable tables but may only INSERT/SELECT `audit_events`. Combined
-- with the append-only triggers, this makes the audit trail tamper-evident even
-- against a compromised application credential — a non-owner cannot DROP the
-- trigger or the table, and the statement-level trigger below blocks TRUNCATE
-- (which does not fire row-level triggers) for everyone, owner included.
--
-- Idempotent so it is safe to re-run: guarded by a role-existence check.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_app') THEN
        GRANT USAGE ON SCHEMA public TO iam_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON
            orgs, principals, credentials, roles, role_permissions, principal_roles, one_time_codes
            TO iam_app;
        -- Append-only for the app role: no UPDATE/DELETE on the audit trail.
        GRANT SELECT, INSERT ON audit_events TO iam_app;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO iam_app;
    END IF;
END
$$;

CREATE TRIGGER audit_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_audit_mutation();
