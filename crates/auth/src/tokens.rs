//! Session tokens: EdDSA (Ed25519) JWTs with a rotatable key ring.
//!
//! The active key signs; every key in the ring verifies. Rotation is therefore
//! overlapping and non-disruptive: add a new key, deploy so all instances know
//! it, flip `active`, and only later retire the old key once no unexpired token
//! still carries its `kid`.
//!
//! Keys are supplied by a [`SigningKeySource`]. Locally that is an env var; in
//! deployed environments a Secrets Manager implementation slots in behind the
//! same trait (that implementation lives with the other AWS code, not here).

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::AuthError;

/// Claims carried by a session token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject: the principal id.
    pub sub: String,
    /// The principal's org id.
    pub org: String,
    /// Session id — the revocable authority in DynamoDB. A valid signature is
    /// necessary but not sufficient; the session must still be live.
    pub sid: String,
    /// Assurance under which the session was established.
    pub assurance: String,
    pub iss: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
}

/// Supplies signing key material. Implementations return, per key id, the
/// PKCS#8 DER bytes of an Ed25519 private key.
pub trait SigningKeySource {
    /// The kid whose key should sign new tokens.
    fn active_kid(&self) -> Result<String, AuthError>;
    /// All known kids and their PKCS#8 DER private keys. All of these verify.
    fn keys(&self) -> Result<BTreeMap<String, Vec<u8>>, AuthError>;
}

/// Reads keys from a JSON env var:
/// `{"active":"dev1","keys":{"dev1":"<base64 PKCS#8 DER>"}}`.
pub struct EnvKeySource {
    active: String,
    keys: BTreeMap<String, Vec<u8>>,
}

#[derive(Deserialize)]
struct EnvKeysJson {
    active: String,
    keys: BTreeMap<String, String>,
}

impl EnvKeySource {
    /// Parse from the raw env var value.
    pub fn from_json(raw: &str) -> Result<Self, AuthError> {
        let parsed: EnvKeysJson = serde_json::from_str(raw)?;
        let mut keys = BTreeMap::new();
        for (kid, b64) in parsed.keys {
            let der = B64
                .decode(b64.trim())
                .map_err(|e| AuthError::InvalidKeyMaterial(format!("kid {kid}: {e}")))?;
            keys.insert(kid, der);
        }
        if !keys.contains_key(&parsed.active) {
            return Err(AuthError::Config(format!(
                "active kid {} not present in keys",
                parsed.active
            )));
        }
        Ok(Self {
            active: parsed.active,
            keys,
        })
    }
}

impl SigningKeySource for EnvKeySource {
    fn active_kid(&self) -> Result<String, AuthError> {
        Ok(self.active.clone())
    }

    fn keys(&self) -> Result<BTreeMap<String, Vec<u8>>, AuthError> {
        Ok(self.keys.clone())
    }
}

struct RingKey {
    encoding: EncodingKey,
    decoding: DecodingKey,
    /// Raw 32-byte public key, for JWKS.
    public_raw: [u8; 32],
}

/// The live set of keys, ready to sign and verify.
pub struct KeyRing {
    active_kid: String,
    keys: BTreeMap<String, RingKey>,
    issuer: String,
    audience: String,
}

impl KeyRing {
    /// Build from a key source and the token's issuer/audience identity.
    pub fn load(
        source: &dyn SigningKeySource,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self, AuthError> {
        let active_kid = source.active_kid()?;
        let raw_keys = source.keys()?;
        if raw_keys.is_empty() {
            return Err(AuthError::NoSigningKey);
        }

        let mut keys = BTreeMap::new();
        for (kid, der) in raw_keys {
            let signing = SigningKey::from_pkcs8_der(&der)
                .map_err(|e| AuthError::InvalidKeyMaterial(format!("kid {kid}: {e}")))?;
            let public_raw = signing.verifying_key().to_bytes();
            keys.insert(
                kid,
                RingKey {
                    encoding: EncodingKey::from_ed_der(&der),
                    decoding: DecodingKey::from_ed_der(&public_raw),
                    public_raw,
                },
            );
        }

        if !keys.contains_key(&active_kid) {
            return Err(AuthError::UnknownKeyId(active_kid));
        }

        Ok(Self {
            active_kid,
            keys,
            issuer: issuer.into(),
            audience: audience.into(),
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Sign a token for a principal + session with the active key.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        &self,
        principal_id: &str,
        org_id: &str,
        session_id: &str,
        assurance: &str,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<String, AuthError> {
        let key = self
            .keys
            .get(&self.active_kid)
            .ok_or(AuthError::NoSigningKey)?;
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.active_kid.clone());

        let claims = Claims {
            sub: principal_id.to_string(),
            org: org_id.to_string(),
            sid: session_id.to_string(),
            assurance: assurance.to_string(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            iat: issued_at.unix_timestamp(),
            exp: expires_at.unix_timestamp(),
        };
        Ok(encode(&header, &claims, &key.encoding)?)
    }

    /// Verify a token: signature (by kid), issuer, audience, and — unless
    /// `validate_exp` is false — expiry. Refresh passes `false` so an expired
    /// but otherwise valid token can be exchanged while the session is live.
    pub fn verify(&self, token: &str, validate_exp: bool) -> Result<Claims, AuthError> {
        let header = decode_header(token)?;
        let kid = header.kid.ok_or(AuthError::MissingKeyId)?;
        let key = self
            .keys
            .get(&kid)
            .ok_or_else(|| AuthError::UnknownKeyId(kid.clone()))?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.validate_exp = validate_exp;
        if !validate_exp {
            // Still require the claim to be present and well-formed.
            validation.required_spec_claims.remove("exp");
        }

        let data = decode::<Claims>(token, &key.decoding, &validation)?;
        Ok(data.claims)
    }

    /// The public key ring as a JWKS document for local verification by
    /// ecosystem services. Hand-rolled: jsonwebtoken has no JWKS emitter.
    pub fn jwks(&self) -> serde_json::Value {
        let jwks: Vec<serde_json::Value> = self
            .keys
            .iter()
            .map(|(kid, key)| {
                serde_json::json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "alg": "EdDSA",
                    "use": "sig",
                    "kid": kid,
                    "x": B64URL.encode(key.public_raw),
                })
            })
            .collect();
        serde_json::json!({ "keys": jwks })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn keygen_der_b64() -> String {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let signing = SigningKey::from_bytes(&seed);
        B64.encode(signing.to_pkcs8_der().unwrap().as_bytes())
    }

    /// A stable set of key material, so multiple rings can be built over the
    /// same keys (to test rotation and audience independently of signatures).
    fn key_json(kids: &[&str]) -> BTreeMap<String, String> {
        kids.iter()
            .map(|k| (k.to_string(), keygen_der_b64()))
            .collect()
    }

    fn ring(
        active: &str,
        keys: &BTreeMap<String, String>,
        issuer: &str,
        audience: &str,
    ) -> KeyRing {
        let json = serde_json::json!({ "active": active, "keys": keys }).to_string();
        let src = EnvKeySource::from_json(&json).unwrap();
        KeyRing::load(&src, issuer, audience).unwrap()
    }

    #[test]
    fn sign_and_verify_round_trips() {
        let keys = key_json(&["k1"]);
        let r = ring("k1", &keys, "iam-test", "ecosystem");
        let now = OffsetDateTime::now_utc();
        let token = r
            .sign(
                "pid",
                "oid",
                "sid",
                "cryptographic",
                now,
                now + Duration::minutes(15),
            )
            .unwrap();
        let claims = r.verify(&token, true).unwrap();
        assert_eq!(claims.sub, "pid");
        assert_eq!(claims.sid, "sid");
        assert_eq!(claims.aud, "ecosystem");
    }

    #[test]
    fn a_token_signed_under_the_old_kid_still_verifies_after_rotation() {
        // Two keys exist. Sign while k1 is active, then rotate active to k2
        // over the SAME key material: the old token must still verify because
        // k1 remains in the ring — this is the overlapping-validity guarantee.
        let keys = key_json(&["k1", "k2"]);
        let before = ring("k1", &keys, "iam-test", "ecosystem");
        let now = OffsetDateTime::now_utc();
        let token = before
            .sign(
                "pid",
                "oid",
                "sid",
                "asserted",
                now,
                now + Duration::minutes(15),
            )
            .unwrap();

        let after = ring("k2", &keys, "iam-test", "ecosystem");
        let claims = after.verify(&token, true).unwrap();
        assert_eq!(claims.sub, "pid");

        // Once k1 is retired from the ring entirely, the old token no longer
        // verifies.
        let only_k2 = key_json(&["k2"]);
        // Reuse k2's material from the shared set so k2 signatures would still
        // match; k1 is simply absent.
        let mut retired = only_k2.clone();
        retired.insert("k2".into(), keys["k2"].clone());
        let retired_ring = ring("k2", &retired, "iam-test", "ecosystem");
        assert!(retired_ring.verify(&token, true).is_err());
    }

    #[test]
    fn expired_token_fails_normal_verify_but_passes_refresh_verify() {
        let keys = key_json(&["k1"]);
        let r = ring("k1", &keys, "iam-test", "ecosystem");
        let past = OffsetDateTime::now_utc() - Duration::hours(2);
        let token = r
            .sign(
                "pid",
                "oid",
                "sid",
                "cryptographic",
                past,
                past + Duration::minutes(15),
            )
            .unwrap();

        assert!(
            r.verify(&token, true).is_err(),
            "expired token must fail strict verify"
        );
        let claims = r.verify(&token, false).unwrap();
        assert_eq!(claims.sub, "pid");
    }

    #[test]
    fn wrong_audience_is_rejected_even_with_a_valid_signature() {
        // Same key material, different audience → signature is fine but the
        // audience claim check fails.
        let keys = key_json(&["k1"]);
        let signer = ring("k1", &keys, "iam-test", "ecosystem");
        let verifier = ring("k1", &keys, "iam-test", "different-audience");
        let now = OffsetDateTime::now_utc();
        let token = signer
            .sign(
                "pid",
                "oid",
                "sid",
                "asserted",
                now,
                now + Duration::minutes(15),
            )
            .unwrap();
        assert!(verifier.verify(&token, true).is_err());
    }

    #[test]
    fn jwks_exposes_every_kid() {
        let keys = key_json(&["k1", "k2"]);
        let r = ring("k1", &keys, "iam-test", "ecosystem");
        let jwks = r.jwks();
        let arr = jwks["keys"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert!(
            arr.iter()
                .all(|k| k["kty"] == "OKP" && k["crv"] == "Ed25519" && k["x"].is_string())
        );
    }
}
