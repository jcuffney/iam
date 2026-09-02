//! Runtime configuration, read from the environment.

use std::time::Duration;

/// Everything the service needs to boot. Loaded once at startup.
#[derive(Clone)]
pub struct Config {
    pub database_url: String,
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
        Ok(Self {
            database_url: req("DATABASE_URL")?,
            connections_database_url: req("CONNECTIONS_DATABASE_URL")?,
            dynamo_endpoint: std::env::var("DYNAMO_ENDPOINT").ok(),

            rp_id: req("IAM_RP_ID")?,
            rp_origin: req("IAM_RP_ORIGIN")?,
            rp_name: std::env::var("IAM_RP_NAME").unwrap_or_else(|_| "iam".to_string()),

            signing_keys_json: req("IAM_SIGNING_KEYS")?,
            connections_enc_key: req("IAM_CONNECTIONS_ENC_KEY")?,

            issuer: req("IAM_ISSUER")?,
            audience: req("IAM_AUDIENCE")?,
            token_ttl: Duration::from_secs(env_u64("IAM_TOKEN_TTL_SECS", 900)),
            session_ttl: Duration::from_secs(env_u64("IAM_SESSION_TTL_SECS", 43_200)),

            listen_addr: std::env::var("IAM_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
        })
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
