//! Account recovery: redeem a one-time recovery code for a limited session that
//! can only add a new credential.
//!
//! This is the path back for a principal that has lost every device. The
//! resulting session is scoped `CredentialRegistrationOnly`, so a redeemed code
//! grants exactly enough to enroll a new passkey and nothing more.

use axum::Json;
use axum::extract::State;
use iam_core::{Assurance, AuditDecision};
use iam_store::{CodePurpose, SessionRecord, SessionScope};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::{self, AuditEntry};
use crate::error::{ApiError, ApiResult};
use crate::ip::ClientIp;
use crate::ratelimit::enforce_principal;
use crate::routes::auth::TokenResponse;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct RecoverRequest {
    pub org_slug: String,
    pub handle: String,
    pub code: String,
}

/// POST /recover — redeem a recovery code, returning a recovery-scoped token.
pub async fn recover(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<RecoverRequest>,
) -> ApiResult<Json<TokenResponse>> {
    let org = state
        .identity()
        .get_org_by_slug(&req.org_slug)
        .await
        .map_err(|_| ApiError::Unauthorized("recovery failed".into()))?;
    let principal = state
        .identity()
        .get_principal_by_handle(org.id, &req.handle)
        .await
        .map_err(|_| ApiError::Unauthorized("recovery failed".into()))?;

    enforce_principal(&state, principal.id.0)?;

    if principal.is_disabled() {
        return Err(ApiError::Unauthorized("recovery failed".into()));
    }

    // Verify + consume a recovery code.
    crate::routes::register::consume_one_time_code(&state, principal.id, CodePurpose::Recovery, &req.code)
        .await
        .map_err(|_| {
            // Uniform failure; audited as a deny.
            ApiError::Unauthorized("recovery failed".into())
        })?;

    // Issue a recovery-scoped session: it can ONLY add a credential.
    let now = OffsetDateTime::now_utc();
    let session_id = Uuid::new_v4().to_string();
    let session_expires = now + state.session_ttl();
    state
        .sessions()
        .put_session(&SessionRecord {
            session_id: session_id.clone(),
            principal_id: principal.id,
            org_id: org.id,
            // A recovery code is an assertion of possession, not a live
            // cryptographic proof — mark it Asserted.
            assurance: Assurance::Asserted,
            scope: SessionScope::CredentialRegistrationOnly,
            created_at: now,
            expires_at: session_expires,
        })
        .await?;

    let token_expires = now + state.token_ttl();
    let token = state
        .keyring()
        .sign(
            &principal.id.to_string(),
            &org.id.to_string(),
            &session_id,
            Assurance::Asserted.to_string().as_str(),
            now,
            token_expires,
        )
        .map_err(|e| ApiError::Internal(e.into()))?;

    audit::record(
        &state,
        AuditEntry {
            org_id: org.id,
            actor_id: principal.id,
            asserted_id: None,
            action: "recover".into(),
            decision: AuditDecision::Allow,
            assurance: Some(Assurance::Asserted),
            reason: Some("recovery code redeemed".into()),
            ip,
        },
    )
    .await;

    Ok(Json(TokenResponse { token, principal_id: principal.id, expires_at: token_expires, assurance: Assurance::Asserted }))
}
