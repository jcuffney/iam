//! Generate local key material.
//!
//! Prints an `IAM_SIGNING_KEYS` value (one Ed25519 key) and an
//! `IAM_CONNECTIONS_ENC_KEY` value (32 random bytes). For local development
//! only — deployed environments source these from AWS Secrets Manager.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;

fn main() -> anyhow::Result<()> {
    let kid = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "dev1".to_string());

    // Signing key: Ed25519 private key as PKCS#8 DER, base64-encoded.
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)?;
    let signing = SigningKey::from_bytes(&seed);
    let pkcs8_der = signing.to_pkcs8_der()?;
    let signing_b64 = B64.encode(pkcs8_der.as_bytes());

    let signing_keys = serde_json::json!({
        "active": kid,
        "keys": { kid: signing_b64 },
    });

    // Connections encryption key: 32 random bytes, base64-encoded.
    let mut enc_key = [0u8; 32];
    getrandom::fill(&mut enc_key)?;
    let enc_b64 = B64.encode(enc_key);

    println!("# Add these to your .env (local development only).");
    println!("# IAM_SIGNING_KEYS is single-quoted so dotenvy keeps the JSON literal.");
    println!();
    // Single quotes: dotenvy strips double quotes from unquoted values.
    println!("IAM_SIGNING_KEYS='{}'", signing_keys);
    println!("IAM_CONNECTIONS_ENC_KEY={}", enc_b64);

    Ok(())
}
