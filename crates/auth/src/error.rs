use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("webauthn ceremony failed: {0}")]
    Webauthn(#[from] webauthn_rs::prelude::WebauthnError),

    /// The signature counter went backwards (or failed to advance where it
    /// should): a strong signal the authenticator was cloned.
    #[error("credential may be cloned: signature counter regressed")]
    CounterRegression,

    #[error("token error: {0}")]
    Token(#[from] jsonwebtoken::errors::Error),

    #[error("no signing key is configured")]
    NoSigningKey,

    #[error("unknown key id: {0}")]
    UnknownKeyId(String),

    #[error("token is missing a key id header")]
    MissingKeyId,

    #[error("invalid signing key material: {0}")]
    InvalidKeyMaterial(String),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("configuration error: {0}")]
    Config(String),
}
