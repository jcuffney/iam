//! Wiring that assembles the concrete stores into an [`AppState`].
//!
//! Shared by the `iam` server and the `seed` bin so store construction lives in
//! one place. This is the only spot that names the Postgres/DynamoDB
//! implementations; handlers only ever see the traits.

use std::sync::Arc;

use iam_auth::{EnvKeySource, KeyRing, WebauthnService};
use iam_connections::{ConnectionsStore, EncryptionKey, PgConnectionsStore};
use iam_policy::{InMemoryInvocationLedger, InMemorySpendLedger};
use iam_store::{DynamoStore, PgStore};
use metrics_exporter_prometheus::PrometheusHandle;

use crate::config::Config;
use crate::state::{AppState, AppStateParts, RateLimiters};

/// The assembled state plus a couple of handles `main` needs to run background
/// tasks (the refresh loop and rate-limiter housekeeping).
pub struct Built {
    pub state: AppState,
    pub connections: Arc<dyn ConnectionsStore>,
    pub limiters: Arc<RateLimiters>,
}

/// How many credential requests per key per minute before limiting kicks in.
const RATE_PER_MINUTE: u32 = 30;

/// Connect every store, run migrations, ensure DynamoDB tables, and build the
/// application state. Idempotent; safe to call on startup and from the seed bin.
pub async fn build(config: &Config, metrics: Option<PrometheusHandle>) -> anyhow::Result<Built> {
    // Identity database (Postgres): identity tree + audit trail.
    let id_pool = iam_store::connect_postgres(&config.database_url, 10).await?;
    iam_store::run_identity_migrations(&id_pool).await?;
    let pg = Arc::new(PgStore::new(id_pool));

    // Connections database (its own pool, role, and encryption key).
    let conn_pool = iam_connections::connect(&config.connections_database_url, 5).await?;
    iam_connections::run_migrations(&conn_pool).await?;
    let enc_key = EncryptionKey::from_base64(&config.connections_enc_key)?;
    let connections: Arc<dyn ConnectionsStore> = Arc::new(PgConnectionsStore::new(conn_pool, enc_key));

    // Ephemeral state (DynamoDB): challenges + sessions.
    let dynamo_client = iam_store::connect_dynamo(config.dynamo_endpoint.as_deref()).await;
    let dynamo = Arc::new(DynamoStore::new(dynamo_client));
    dynamo.ensure_tables().await?;

    let webauthn = Arc::new(WebauthnService::new(&config.rp_id, &config.rp_origin, &config.rp_name)?);

    let key_source = EnvKeySource::from_json(&config.signing_keys_json)?;
    let keyring = Arc::new(KeyRing::load(&key_source, config.issuer.clone(), config.audience.clone())?);

    let limiters = Arc::new(RateLimiters::new(RATE_PER_MINUTE));

    let state = AppState::new(AppStateParts {
        identity: pg.clone(),
        audit: pg.clone(),
        challenges: dynamo.clone(),
        sessions: dynamo.clone(),
        connections: connections.clone(),
        webauthn,
        keyring,
        spend: Arc::new(InMemorySpendLedger::new()),
        invocations: Arc::new(InMemoryInvocationLedger::new()),
        token_ttl: config.token_ttl,
        session_ttl: config.session_ttl,
        limiters: limiters.clone(),
        metrics,
    });

    Ok(Built { state, connections, limiters })
}
