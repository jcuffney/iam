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
    /// actually run so a client cannot spoof its source IP.
    pub trusted_proxy_hops: usize,

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
