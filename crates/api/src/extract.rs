//! The authentication extractor.
//!
//! Turns a `Bearer` token into an [`Authenticated`] principal, enforcing the
//! full chain: valid signature (by kid, via the key ring) → live, unexpired
//! session in the session store → principal not disabled. A valid signature
//! alone is never enough; the revocable session is the authority, which is what
//! makes logout and disable take effect immediately.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use iam_core::{Assurance, Principal};
use iam_store::{SessionRecord, SessionScope};
use time::OffsetDateTime;

use crate::error::ApiError;
use crate::state::AppState;

/// An authenticated caller and the session behind the request.
#[derive(Clone)]
pub struct Authenticated {
    pub principal: Principal,
    pub session: SessionRecord,
}

impl Authenticated {
    pub fn assurance(&self) -> Assurance {
        self.session.assurance
    }

    /// Reject a recovery-scoped session. Every endpoint except adding a
    /// credential requires a full session.
    pub fn require_full_scope(&self) -> Result<(), ApiError> {
        match self.session.scope {
            SessionScope::Full => Ok(()),
            SessionScope::CredentialRegistrationOnly => Err(ApiError::Forbidden(
                "this session may only register a new credential".into(),
            )),
        }
    }
}

impl FromRequestParts<AppState> for Authenticated {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts)
            .ok_or_else(|| ApiError::Unauthorized("missing bearer token".into()))?;

        // Signature + issuer + audience + expiry.
        let claims = state
            .keyring()
            .verify(&token, true)
            .map_err(|_| ApiError::Unauthorized("invalid token".into()))?;

        // The session must still be live — this is where revocation bites.
        let now = OffsetDateTime::now_utc();
        let session = state
            .sessions()
            .get_session(&claims.sid, now)
            .await?
            .ok_or_else(|| ApiError::Unauthorized("session expired or revoked".into()))?;

        let principal_id = claims
            .sub
            .parse()
            .map_err(|_| ApiError::Unauthorized("malformed subject".into()))?;
        let principal = state.identity().get_principal(principal_id).await?;

        // A disabled principal cannot act even with a live session.
        if principal.is_disabled() {
            return Err(ApiError::Unauthorized("principal is disabled".into()));
        }

        Ok(Authenticated { principal, session })
    }
}

/// Extract the raw bearer token from the Authorization header.
fn bearer_token(parts: &Parts) -> Option<String> {
    let value = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    Some(token.trim().to_string())
}
