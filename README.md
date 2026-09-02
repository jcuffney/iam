# iam

An identity and authorization service for humans, devices, and agents — the
backbone that answers three questions for everything else in the ecosystem:

1. **Who is this principal?** — WebAuthn passkeys, one account across many devices.
2. **What may this principal do?** — role-based permissions, resolved by a pure policy engine.
3. **What did they actually do?** — an append-only audit trail.

Humans, devices, and agents are all first-class principals in the same
hierarchy. WebAuthn and public/private-key signatures are the underlying
protocols; `iam` is the opinionated implementation on top — the LDAP-to-Active-Directory
relationship, if you like.

> **Security-critical infrastructure.** This code is written to be read again in
> six months. Clarity over cleverness throughout.

---

## The delegation model (read this first)

The heart of the service. A **device may act on behalf of a human, but can never
exceed its own ceiling.**

When the basement gym speaker sends a request, it authenticates as *itself* (its
own passkey) and *asserts* a human identity — from voice recognition, which is an
assertion, not proof. The authorization decision then obeys three rules:

1. **Intersection, never union.** The effective permission set is the
   intersection of the device's role permissions and the asserted human's role
   permissions. The device can't borrow the human's powers, and the human's
   assertion can't unlock powers the device lacks.

2. **Assurance ladder.** Every decision carries an `Assurance` level:
   - `Cryptographic` — the principal's own credential signed the request.
   - `Asserted` — a device vouched for them.

   Permissions declare a minimum assurance. Reading a shared calendar is fine at
   `Asserted`. Reading **private memory**, **approving spend**, **administering
   the org**, or **managing a connection** requires `Cryptographic`.

3. **Both identities are always audited** — the acting device *and* the asserted
   human, on every decision.

The consequence: a voice-asserted human can have the speaker read the family
calendar, but can never have it approve a payment or read private memory — those
need the human's own passkey. This logic lives in [`iam-policy`](crates/policy),
is pure (no IO), and is covered exhaustively by unit tests.

---

## Architecture

One Cargo workspace, six crates, dependencies pointing in one direction only.
`core` depends on nothing of ours; `api` depends on everything.

| Crate | Responsibility |
|---|---|
| [`iam-core`](crates/core) | Domain types only (serde/uuid/time). Principals, credentials, permissions, assurance, audit, and the connection/capability/grant model. |
| [`iam-policy`](crates/policy) | **Pure** authorization functions over core types. The intersection rule, the assurance ladder, capability-grant evaluation. No IO. |
| [`iam-auth`](crates/auth) | WebAuthn ceremonies, the rotatable EdDSA token key ring (+ JWKS), and one-time recovery/registration codes. |
| [`iam-store`](crates/store) | The durable identity tree (Postgres) and ephemeral challenges/sessions (DynamoDB), behind traits with in-memory implementations for tests. |
| [`iam-connections`](crates/connections) | Outbound credentials (OAuth grants, API keys, MCP auth). **Store-isolated** — see below. |
| [`iam-api`](crates/api) | The only crate that knows HTTP. `axum` handlers, the `iam`/`seed`/`keygen` binaries. |

`Credential` is modeled as an enum with a `Passkey` variant today so a `Wallet`
variant can be added later without reshaping anything.

### Two databases, on purpose

`iam-store` holds public keys — not secret. `iam-connections` holds live bearer
tokens that can act against third-party systems *right now*. They live in
**separate databases with separate credentials and a separate encryption key**,
so one SQL injection cannot expose both. `iam-connections` never shares a pool or
handle with `iam-store`.

---

## Local development

The whole developer loop is `cargo run` against a Postgres container and
DynamoDB Local. No Lambda emulation, no containers in the hot path.

### Prerequisites

- Rust stable (see [`rust-toolchain.toml`](rust-toolchain.toml))
- Docker + Docker Compose
- `pkg-config`, `libssl-dev` (or your platform's OpenSSL headers) and a C
  compiler — `webauthn-rs` links system OpenSSL.
- [`sqlx-cli`](https://crates.io/crates/sqlx-cli) `0.8.x` for migrations:
  `cargo install sqlx-cli --version ^0.8`

### Setup

```bash
# 1. Start Postgres (two isolated databases) and DynamoDB Local.
docker compose up -d

# 2. Generate local signing + encryption keys.
cargo run -p iam-api --bin keygen

# 3. Copy the example env and paste in the keygen output.
cp .env.example .env
$EDITOR .env    # set IAM_SIGNING_KEYS and IAM_CONNECTIONS_ENC_KEY

# 4. Run the service. Migrations run and DynamoDB tables are ensured on startup.
cargo run -p iam-api

# 5. In another shell, seed the dev fixture (one org, two humans, a device, an agent).
cargo run -p iam-api --bin seed
```

`GET http://localhost:8080/health` should return `{"status":"ok"}`.

> **`IAM_SIGNING_KEYS` must be single-quoted in `.env`** — dotenvy strips double
> quotes from unquoted values, and the value is JSON. `keygen` prints it
> correctly.

### The seeded fixture

`seed` creates the org `cuffney`, the five standard roles, and:

| Handle | Kind | Role |
|---|---|---|
| `joe` | human | admin |
| `jane` | human | user |
| `gym-speaker` | device | device |
| `jarvis` | agent | agent |

It prints each principal's **registration token** (and recovery codes for
humans) exactly once — those bind the first credential.

---

## HTTP surface

| Endpoint | Purpose |
|---|---|
| `POST /register/start` | Challenge to bind the first credential (needs a registration token). |
| `POST /register/finish` | Verify and persist the credential. Idempotent. |
| `POST /register/device/start` | Add a credential to an **existing authenticated** principal — so a second device attaches to the same account. |
| `POST /auth/start` · `/auth/finish` | Assertion ceremony → session + token. |
| `POST /auth/refresh` · `/auth/logout` | Refresh a token (session is the authority) / revoke the session. |
| `POST /authorize` | `{ asserted_principal?, action, capability? }` → decision + assurance. |
| `GET /principals/{id}` · `POST /principals` | Inspect / create (admin only; returns recovery codes + registration token once). |
| `PUT·DELETE /principals/{id}/roles/{role}` | Assign / revoke a role. |
| `POST /principals/{id}/disable` · `/enable` | Suspend / restore a principal (neutralizes live sessions immediately). |
| `POST /principals/{id}/recovery-codes` | Reissue recovery codes. |
| `DELETE /credentials/{id}` | Revoke a lost/stolen passkey. |
| `GET /audit` | Filterable audit query (admin). |
| `POST /recover` | Redeem a recovery code → a session scoped to *only* add a credential. |
| `POST·GET /connections`, `DELETE /connections/{id}` | Manage outbound connections. |
| `POST /grants`, `DELETE /grants/{id}` | Grant / revoke capability access. |
| `GET /health` · `GET /metrics` · `GET /.well-known/jwks.json` | Liveness, Prometheus counters, public keys. |

### Integrating a service

Ecosystem services (jarvis, the homelab stack, …) should:

- **Authenticate** by verifying the EdDSA JWT locally against
  `GET /.well-known/jwks.json`, honoring `exp`, `iss`, and `aud`. Access tokens
  are short-lived (~15 min); revocation propagates within one token lifetime.
- **Authorize** by calling `POST /authorize`, which is always session-fresh and
  applies the full delegation + assurance logic. Do not reimplement the rules.

---

## Connections, capabilities, and grants

Three distinct concepts, modeled separately in `iam-core`:

- **Connection** — an outbound authenticated relationship (an OAuth grant, an API
  key, an MCP server credential). A bearer secret pointing at someone else's
  system. The secret is encrypted in `iam-connections`; only metadata is ever
  returned.
- **Capability** — a specific invocable operation. An MCP server *describes* its
  tools, so `mcp:filesystem.read` is grantable independently of
  `mcp:filesystem.write`; a raw API key is opaque and grantable only as a whole
  (`*`). The type says which.
- **Grant** — the object-capability binding `iam-policy` evaluates: a principal
  may invoke a capability, under constraints (rate limit, time window, spend
  cap), until expiry or revocation. Revocation — of the grant *or the connection
  behind it* — is immediate and total.

Because `capability:invoke` and `connection:manage` are ordinary permissions,
the delegation rule applies automatically: a voice-asserted device can *use* a
granted capability, but can never *create or revoke* a grant (that needs
`connection:manage`, which is `Cryptographic`-only).

**Metered spend** (`Constraint::Spend`) is evaluated against a `SpendLedger`
trait *before* invocation is authorized. Only an in-memory implementation ships
today; that trait boundary is where a wallet/escrow layer plugs in later.

---

## Cross-cutting guarantees

- **Recovery.** One-time recovery codes are generated at principal creation,
  stored argon2id-hashed, and shown once. A principal that loses every device
  redeems one at `POST /recover` for a session that can *only* enroll a new
  credential.
- **Key rotation.** The token-signing key ring signs with the active key and
  verifies against all listed keys, so rotation is overlapping and
  non-disruptive: add a key, deploy, flip `active`, retire the old key later.
  Keys come from `IAM_SIGNING_KEYS` locally and AWS Secrets Manager when
  deployed (same trait).
- **Rate limiting** on credential endpoints, keyed by IP (pre-auth) and by
  principal (post-auth). In-process — see the deployment note.
- **Idempotent registration.** A retried finish never creates a duplicate
  credential.
- **Audit as a first-class write path** — a real store write awaited before the
  response, not a `tracing` side effect. The table is append-only (enforced by a
  database trigger).
- **Cloned-authenticator detection.** The WebAuthn signature counter is validated
  on every assertion; a regression is rejected and audited as a possible
  compromise.

### ⚠️ Passkeys are scoped to `IAM_RP_ID`

WebAuthn credentials are bound to the relying-party domain. Registering against
`localhost` and later moving to `iam.example.com` **strands every credential** —
there is no migration. **Pick the production domain before the first real
registration.**

---

## Testing

```bash
cargo test --workspace     # no containers required
```

- `iam-policy`: the intersection rule and the assurance ladder, exhaustively,
  over every permission.
- `iam-api` (`tests/integration.rs`): both full WebAuthn ceremonies via a virtual
  authenticator (`SoftPasskey`), the device-can't-exceed-ceiling rule,
  `Asserted`-refused-for-private-memory, second-device-same-account,
  idempotent finish, clone detection, session lifecycle, and the full
  capability/grant model — all in-process, no containers.
- Store integration tests that need live Postgres/DynamoDB are marked `#[ignore]`;
  run them with the containers up: `cargo test --workspace -- --ignored`.

### Offline builds

sqlx queries are checked at compile time. Committed metadata in `.sqlx/` lets
`SQLX_OFFLINE=true cargo build` work without a database (this is how CI builds).
After changing a query, regenerate it with the containers up:

```bash
cargo sqlx prepare --workspace
```

---

## Deployment notes

- **Lambda.** The handler logic is runtime-agnostic: `build_router` returns a
  plain `axum::Router`, and the `lambda` cargo feature swaps the native server
  for `lambda_http::run` (with vendored OpenSSL). No Lambda types leak into
  handler signatures. Build with `cargo lambda` behind API Gateway.
- **Secrets.** `IAM_SIGNING_KEYS` and `IAM_CONNECTIONS_ENC_KEY` come from AWS
  Secrets Manager in deployed environments. **Back up `IAM_CONNECTIONS_ENC_KEY`
  out of band** — losing it makes every stored connection secret unrecoverable,
  by design.
- **Rate limiting is per-instance** (in-process). Across many Lambda instances it
  is best-effort; the real brute-force backstop is argon2 hashing plus single-use
  codes. A distributed limiter can be slotted in behind the same seam later.
- **`/metrics` is unauthenticated** — protect it at the network layer when
  deployed.

## License

MIT — see [LICENSE](LICENSE).
