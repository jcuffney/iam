//! Runtime configuration, read from the environment.

use std::time::Duration;

/// Everything the service needs to boot. Loaded once at startup.
#[derive(Clone)]
pub struct Config {
    /// The role the service *serves* as. In the hardened setup this is the
    /// non-owner `iam_app` role, so a compromised app credential cannot mutate
    /// the append-only audit table.
    pub database_url: String,
    /// The owner role used ONLY to run migrations (DDL). Falls back to
    /// `database_url` when unset, which keeps the single-role dev setup working.
    pub migration_database_url: Option<String>,
    pub connections_database_url: String,
    pub dynamo_endpoint: Option<String>,

    /// Whether startup performs DDL (Postgres migrations + DynamoDB table
    /// creation). `true` (the default) keeps the dev loop a plain `cargo run`;
    /// deployed environments set `false` — IaC owns the tables, the `admin`
    /// binary owns migrations, and the serving role holds no DDL credentials.
    pub bootstrap: bool,

    /// DynamoDB table names, so the runtime follows whatever IaC created.
    /// Defaults match the names dev bootstrap creates.
    pub dynamo_challenges_table: String,
    pub dynamo_sessions_table: String,

    /// Max connections for the identity / connections pools. Deployed Lambda
    /// sandboxes serve one request at a time and share a small database, so
    /// they run these far lower than the dev defaults.
    pub db_pool_max: u32,
    pub connections_pool_max: u32,

    pub rp_id: String,
    pub rp_origin: String,
    pub rp_name: String,

    pub signing_keys_json: String,
    pub connections_enc_key: String,

    pub issuer: String,
    pub audience: String,
    pub token_ttl: Duration,
    pub session_ttl: Duration,

    /// Number of trusted reverse-proxy hops in front of the service. `0` (the
    /// default) means do NOT trust `X-Forwarded-For` at all — the client IP
    /// comes only from the connection. Set this to the count of proxies you
    /// actually run so a client cannot spoof its source IP. Keep it 0 behind
    /// API Gateway: the Lambda entry point surfaces the gateway's `sourceIp`
    /// (which is authoritative) as the connection peer instead.
    pub trusted_proxy_hops: usize,

    /// When set, `GET /metrics` requires `Authorization: Bearer <token>`.
    /// Unset (dev) leaves it open — deployed environments must set it, since
    /// the API edge forwards every path to the router.
    pub metrics_token: Option<String>,

    pub listen_addr: String,
}

#[derive(Debug, thiserror::Error)]
#[error("missing required environment variable: {0}")]
pub struct MissingVar(String);

fn req(key: &str) -> Result<String, MissingVar> {
    std::env::var(key).map_err(|_| MissingVar(key.to_string()))
}

impl Config {
    /// Load from the environment (after `.env` has been sourced by the binary).
    pub fn from_env() -> Result<Self, MissingVar> {
        let token_ttl = Duration::from_secs(env_u64("IAM_TOKEN_TTL_SECS", 900));
        let session_ttl = Duration::from_secs(env_u64("IAM_SESSION_TTL_SECS", 43_200));
        // The session is the revocation authority; a token outliving its session
        // is a misconfiguration, so surface it rather than silently accept it.
        if token_ttl > session_ttl {
            tracing::warn!(
                token_ttl_secs = token_ttl.as_secs(),
                session_ttl_secs = session_ttl.as_secs(),
                "IAM_TOKEN_TTL_SECS exceeds IAM_SESSION_TTL_SECS; tokens will be capped at the session expiry"
            );
        }

        Ok(Self {
            database_url: req("DATABASE_URL")?,
            migration_database_url: std::env::var("IAM_MIGRATION_DATABASE_URL").ok(),
            connections_database_url: req("CONNECTIONS_DATABASE_URL")?,
            dynamo_endpoint: std::env::var("DYNAMO_ENDPOINT").ok(),

            bootstrap: env_bool("IAM_BOOTSTRAP", true),
            dynamo_challenges_table: std::env::var("IAM_DYNAMO_CHALLENGES_TABLE")
                .unwrap_or_else(|_| iam_store::CHALLENGES_TABLE.to_string()),
            dynamo_sessions_table: std::env::var("IAM_DYNAMO_SESSIONS_TABLE")
                .unwrap_or_else(|_| iam_store::SESSIONS_TABLE.to_string()),
            db_pool_max: env_u64("IAM_DB_POOL_MAX", 10) as u32,
            connections_pool_max: env_u64("IAM_CONNECTIONS_POOL_MAX", 5) as u32,

            rp_id: req("IAM_RP_ID")?,
            rp_origin: req("IAM_RP_ORIGIN")?,
            rp_name: std::env::var("IAM_RP_NAME").unwrap_or_else(|_| "iam".to_string()),

            signing_keys_json: req("IAM_SIGNING_KEYS")?,
            connections_enc_key: req("IAM_CONNECTIONS_ENC_KEY")?,

            issuer: req("IAM_ISSUER")?,
            audience: req("IAM_AUDIENCE")?,
            token_ttl,
            session_ttl,
            trusted_proxy_hops: env_u64("IAM_TRUSTED_PROXY_HOPS", 0) as usize,
            metrics_token: std::env::var("IAM_METRICS_TOKEN")
                .ok()
                .filter(|t| !t.is_empty()),

            listen_addr: std::env::var("IAM_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
        })
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    match std::env::var(key) {
        Ok(raw) => match raw.parse() {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(key, value = %raw, default, "malformed numeric env var; using default");
                default
            }
        },
        Err(_) => default,
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(raw) => match raw.to_ascii_lowercase().as_str() {
            "true" | "1" => true,
            "false" | "0" => false,
            _ => {
                tracing::warn!(key, value = %raw, default, "malformed boolean env var; using default");
                default
            }
        },
        Err(_) => default,
    }
}
