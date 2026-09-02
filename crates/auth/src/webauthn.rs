//! WebAuthn registration and assertion, wrapped so the rest of the service
//! deals in iam-core types and opaque state blobs rather than webauthn-rs
//! internals.
//!
//! The ceremony state ([`PasskeyRegistration`]/[`PasskeyAuthentication`]) is
//! serialized to bytes here and parked in the ephemeral challenge store between
//! the start and finish calls; the durable [`iam_core::PasskeyCredential`] blob
//! is likewise this crate's serialization of a webauthn-rs `Passkey`.

use iam_core::PasskeyCredential;
use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, Url, Webauthn, WebauthnBuilder,
};

use crate::error::AuthError;

/// Thin wrapper over a configured `Webauthn` relying party.
///
/// WARNING: passkeys are scoped to `rp_id`. Changing the domain after real
/// credentials exist strands every one of them — there is no migration. Pick
/// the production domain before the first real registration.
pub struct WebauthnService {
    inner: Webauthn,
}

/// Result of finishing a registration: the durable credential to persist, plus
/// the raw credential id for idempotency lookups.
pub struct RegisteredCredential {
    pub credential: PasskeyCredential,
    pub credential_id: Vec<u8>,
}

/// Result of finishing an authentication: which credential was used, and the
/// updated durable blob + counter to write back.
pub struct VerifiedAssertion {
    pub credential_id: Vec<u8>,
    /// Re-serialized passkey blob after `update_credential`; persist it.
    pub updated_blob: Vec<u8>,
    pub sign_count: u32,
    pub verified_at: OffsetDateTime,
}

impl WebauthnService {
    pub fn new(rp_id: &str, rp_origin: &str, rp_name: &str) -> Result<Self, AuthError> {
        let origin = Url::parse(rp_origin).map_err(|e| AuthError::Config(format!("invalid rp origin: {e}")))?;
        let inner = WebauthnBuilder::new(rp_id, &origin)
            .map_err(AuthError::Webauthn)?
            .rp_name(rp_name)
            .build()
            .map_err(AuthError::Webauthn)?;
        Ok(Self { inner })
    }

    /// Begin registering a new passkey for a principal.
    ///
    /// `existing_credential_ids` populates the exclude list so an authenticator
    /// already registered to this principal is refused a duplicate — the same
    /// physical device cannot be enrolled twice.
    pub fn start_registration(
        &self,
        principal_id: Uuid,
        handle: &str,
        display_name: &str,
        existing_credential_ids: &[Vec<u8>],
    ) -> Result<(CreationChallengeResponse, Vec<u8>), AuthError> {
        let exclude: Vec<CredentialID> = existing_credential_ids.iter().cloned().map(CredentialID::from).collect();
        let exclude = if exclude.is_empty() { None } else { Some(exclude) };

        let (ccr, state) = self
            .inner
            .start_passkey_registration(principal_id, handle, display_name, exclude)
            .map_err(AuthError::Webauthn)?;

        let state_blob = serde_json::to_vec(&state)?;
        Ok((ccr, state_blob))
    }

    /// Complete registration: verify the attestation and produce the durable
    /// credential to persist.
    pub fn finish_registration(
        &self,
        principal_id: iam_core::PrincipalId,
        registration: &RegisterPublicKeyCredential,
        state_blob: &[u8],
        nickname: Option<String>,
    ) -> Result<RegisteredCredential, AuthError> {
        let state: PasskeyRegistration = serde_json::from_slice(state_blob)?;
        let passkey = self.inner.finish_passkey_registration(registration, &state).map_err(AuthError::Webauthn)?;
        let credential = passkey_to_core(principal_id, &passkey, nickname)?;
        let credential_id = credential.credential_id.clone();
        Ok(RegisteredCredential { credential, credential_id })
    }

    /// Begin authentication against a principal's registered passkeys.
    pub fn start_authentication(&self, credentials: &[PasskeyCredential]) -> Result<(RequestChallengeResponse, Vec<u8>), AuthError> {
        let passkeys: Vec<Passkey> = credentials
            .iter()
            .map(|c| serde_json::from_slice::<Passkey>(&c.passkey_blob).map_err(AuthError::from))
            .collect::<Result<_, _>>()?;

        let (rcr, state) = self.inner.start_passkey_authentication(&passkeys).map_err(AuthError::Webauthn)?;
        let state_blob = serde_json::to_vec(&state)?;
        Ok((rcr, state_blob))
    }

    /// Complete authentication: verify the assertion and, crucially, validate
    /// the signature counter. A counter regression surfaces as
    /// [`AuthError::CounterRegression`] so the caller can 401 and audit a
    /// possible clone.
    ///
    /// `stored` is the credential the assertion claims to use; its blob is
    /// updated with the new counter/backup flags for write-back.
    pub fn finish_authentication(
        &self,
        assertion: &PublicKeyCredential,
        state_blob: &[u8],
        stored: &PasskeyCredential,
        now: OffsetDateTime,
    ) -> Result<VerifiedAssertion, AuthError> {
        let state: PasskeyAuthentication = serde_json::from_slice(state_blob)?;

        let result = match self.inner.finish_passkey_authentication(assertion, &state) {
            Ok(r) => r,
            // webauthn-rs raises this specifically when the counter shows a
            // possible clone; translate it to our explicit variant.
            Err(webauthn_rs::prelude::WebauthnError::CredentialPossibleCompromise) => {
                return Err(AuthError::CounterRegression);
            }
            Err(e) => return Err(AuthError::Webauthn(e)),
        };

        let mut passkey: Passkey = serde_json::from_slice(&stored.passkey_blob)?;
        passkey.update_credential(&result);

        let updated_blob = serde_json::to_vec(&passkey)?;
        Ok(VerifiedAssertion {
            credential_id: result.cred_id().as_ref().to_vec(),
            updated_blob,
            sign_count: result.counter(),
            verified_at: now,
        })
    }
}

/// Convert a freshly registered webauthn-rs `Passkey` into the durable
/// iam-core credential, mirroring the queryable fields alongside the opaque
/// blob.
fn passkey_to_core(
    principal_id: iam_core::PrincipalId,
    passkey: &Passkey,
    nickname: Option<String>,
) -> Result<PasskeyCredential, AuthError> {
    let credential_id = passkey.cred_id().as_ref().to_vec();
    let passkey_blob = serde_json::to_vec(passkey)?;

    // Read the mirrored fields through the danger-credential-internals view.
    let cred: webauthn_rs::prelude::Credential = passkey.clone().into();
    let transports = cred
        .transports
        .as_ref()
        .map(|ts| ts.iter().map(|t| format!("{t:?}").to_lowercase()).collect())
        .unwrap_or_default();

    Ok(PasskeyCredential {
        credential_id,
        principal_id,
        passkey_blob,
        sign_count: cred.counter,
        transports,
        // None in the plain-passkey (none-attestation) flow — the attestation
        // metadata does not retain an aaguid.
        aaguid: None,
        nickname,
        created_at: OffsetDateTime::now_utc(),
        last_used_at: None,
    })
}
