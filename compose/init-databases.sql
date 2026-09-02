-- Two databases, two roles, no cross-grants.
-- iam-store holds public keys (not secret); iam-connections holds live bearer
-- tokens. A leaked identity-DB credential must not be able to reach the other.

CREATE ROLE iam LOGIN PASSWORD 'iam';
CREATE ROLE iam_connections LOGIN PASSWORD 'iam_connections';

CREATE DATABASE iam OWNER iam;
CREATE DATABASE iam_connections OWNER iam_connections;

-- By default PUBLIC may connect to any database; revoke that so each role can
-- only reach its own store.
REVOKE CONNECT ON DATABASE iam FROM PUBLIC;
REVOKE CONNECT ON DATABASE iam_connections FROM PUBLIC;
GRANT CONNECT ON DATABASE iam TO iam;
GRANT CONNECT ON DATABASE iam_connections TO iam_connections;
