//! Authentication: assertion ceremony, session issuance, token refresh, logout.

use axum::Json;
use axum::extract::State;
use iam_auth::ceremony::{PublicKeyCredential, RequestChallengeResponse};
use iam_core::{Assurance, AuditDecision, Credential, PasskeyCredential, PrincipalId};
use iam_store::{ChallengeMode, ChallengeRecord, SessionRecord, SessionScope};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::audit::{self, AuditEntry};
use crate::error::{ApiError, ApiResult};
use crate::extract::Authenticated;
use crate::ip::ClientIp;
use crate::metrics;
use crate::state::AppState;

const CHALLENGE_TTL: Duration = Duration::minutes(5);

#[derive(Deserialize)]
pub struct AuthStartRequest {
    pub org_slug: String,
    pub handle: String,
}

#[derive(Serialize)]
pub struct AuthStartResponse {
    pub challenge_id: String,
    /// `PublicKeyCredentialRequestOptions` for `navigator.credentials.get`.
    #[serde(rename = "publicKey")]
    pub public_key: RequestChallengeResponse,
}

/// POST /auth/start — issue an assertion challenge over a principal's passkeys.
pub async fn start(
    State(state): State<AppState>,
    Json(req): Json<AuthStartRequest>,
) -> ApiResult<Json<AuthStartResponse>> {
    let org = state
        .identity()
        .get_org_by_slug(&req.org_slug)
        .await
        .map_err(|_| ApiError::Unauthorized("authentication failed".into()))?;
    let principal = state
        .identity()
        .get_principal_by_handle(org.id, &req.handle)
        .await
        .map_err(|_| ApiError::Unauthorized("authentication failed".into()))?;

    // Pre-auth: throttled per-IP by the middleware, never per-target-principal
    // (that would let anyone lock out a victim by handle).
    if principal.is_disabled() {
        return Err(ApiError::Unauthorized("authentication failed".into()));
    }

    let passkeys = passkeys_for(&state, principal.id).await?;
    if passkeys.is_empty() {
        return Err(ApiError::Unauthorized("authentication failed".into()));
    }

    let (rcr, state_blob) = state.webauthn().start_authentication(&passkeys)?;

    let challenge_id = Uuid::new_v4().to_string();
    state
        .challenges()
        .put_challenge(&ChallengeRecord {
            challenge_id: challenge_id.clone(),
            mode: ChallengeMode::Auth,
            principal_id: principal.id,
            org_id: org.id,
            state_blob,
            expires_at: OffsetDateTime::now_utc() + CHALLENGE_TTL,
        })
        .await?;

    Ok(Json(AuthStartResponse {
        challenge_id,
        public_key: rcr,
    }))
}

#[derive(Deserialize)]
pub struct AuthFinishRequest {
    pub challenge_id: String,
    pub credential: PublicKeyCredential,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub principal_id: PrincipalId,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub assurance: Assurance,
}

/// POST /auth/finish — verify the assertion (including the signature counter),
/// establish a session, and issue a token.
pub async fn finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<AuthFinishRequest>,
) -> ApiResult<Json<TokenResponse>> {
    let now = OffsetDateTime::now_utc();
    let raw_id = req.credential.raw_id.as_ref().to_vec();

    let challenge = state
        .challenges()
        .take_challenge(&req.challenge_id, now)
        .await?
        .filter(|c| c.mode == ChallengeMode::Auth)
        .ok_or_else(|| ApiError::BadRequest("unknown or expired challenge".into()))?;

    // Identify the stored credential the assertion used and confirm ownership.
    let Credential::Passkey(stored) = state.identity().get_credential(&raw_id).await?;
    if stored.principal_id != challenge.principal_id {
        return Err(ApiError::Unauthorized(
            "credential does not belong to this principal".into(),
        ));
    }

    // Verify — a counter regression surfaces here as a possible clone.
    let verified = match state.webauthn().finish_authentication(
        &req.credential,
        &challenge.state_blob,
        &stored,
        now,
    ) {
        Ok(v) => v,
        Err(iam_auth::AuthError::CounterRegression) => {
            metrics::counter_regression();
            metrics::auth_attempt("failure");
            audit::record(
                &state,
                AuditEntry {
                    org_id: challenge.org_id,
                    actor_id: challenge.principal_id,
                    asserted_id: None,
                    action: "auth.finish".into(),
                    decision: AuditDecision::Deny,
                    assurance: None,
                    reason: Some("counter_regression".into()),
                    ip,
                },
            )
            .await;
            return Err(ApiError::CredentialCompromise);
        }
        Err(e) => {
            metrics::auth_attempt("failure");
            return Err(e.into());
        }
    };

    // Persist the advanced counter / updated blob.
    let updated = PasskeyCredential {
        credential_id: verified.credential_id.clone(),
        principal_id: stored.principal_id,
        passkey_blob: verified.updated_blob,
        sign_count: verified.sign_count,
        transports: stored.transports.clone(),
        aaguid: stored.aaguid,
        nickname: stored.nickname.clone(),
        created_at: stored.created_at,
        last_used_at: Some(verified.verified_at),
    };
    state
        .identity()
        .update_credential_after_auth(&updated)
        .await?;

    // Establish a session (the revocable authority) and mint a short token.
    let session_id = Uuid::new_v4().to_string();
    let session_expires = now + state.session_ttl();
    state
        .sessions()
        .put_session(&SessionRecord {
            session_id: session_id.clone(),
            principal_id: challenge.principal_id,
            org_id: challenge.org_id,
            assurance: Assurance::Cryptographic,
            scope: SessionScope::Full,
            created_at: now,
            expires_at: session_expires,
        })
        .await?;

    let token_expires = now + state.token_ttl();
    let token = state
        .keyring()
        .sign(
            &challenge.principal_id.to_string(),
            &challenge.org_id.to_string(),
            &session_id,
            Assurance::Cryptographic.to_string().as_str(),
            now,
            token_expires,
        )
        .map_err(|e| ApiError::Internal(e.into()))?;

    metrics::auth_attempt("success");
    audit::record(
        &state,
        AuditEntry {
            org_id: challenge.org_id,
            actor_id: challenge.principal_id,
            asserted_id: None,
            action: "auth.finish".into(),
            decision: AuditDecision::Allow,
            assurance: Some(Assurance::Cryptographic),
            reason: None,
            ip,
        },
    )
    .await;

    Ok(Json(TokenResponse {
        token,
        principal_id: challenge.principal_id,
        expires_at: token_expires,
        assurance: Assurance::Cryptographic,
    }))
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub token: String,
}

/// POST /auth/refresh — exchange a still-signed token (expiry ignored) for a
/// fresh one, provided its session is still live. The token never outlives the
/// session.
pub async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> ApiResult<Json<TokenResponse>> {
    let claims = state
        .keyring()
        .verify(&req.token, false)
        .map_err(|_| ApiError::Unauthorized("invalid token".into()))?;

    let now = OffsetDateTime::now_utc();
    let session = state
        .sessions()
        .get_session(&claims.sid, now)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("session expired or revoked".into()))?;

    let principal_id: PrincipalId = claims
        .sub
        .parse()
        .map_err(|_| ApiError::Unauthorized("malformed subject".into()))?;
    let principal = state.identity().get_principal(principal_id).await?;
    if principal.is_disabled() {
        return Err(ApiError::Unauthorized("principal is disabled".into()));
    }

    // Cap the new token at the session's expiry.
    let token_expires = (now + state.token_ttl()).min(session.expires_at);
    let token = state
        .keyring()
        .sign(
            &claims.sub,
            &claims.org,
            &session.session_id,
            session.assurance.to_string().as_str(),
            now,
            token_expires,
        )
        .map_err(|e| ApiError::Internal(e.into()))?;

    Ok(Json(TokenResponse {
        token,
        principal_id,
        expires_at: token_expires,
        assurance: session.assurance,
    }))
}

/// POST /auth/logout — revoke the current session.
pub async fn logout(
    State(state): State<AppState>,
    auth: Authenticated,
) -> ApiResult<Json<serde_json::Value>> {
    state
        .sessions()
        .revoke_session(&auth.session.session_id)
        .await?;
    audit::record(
        &state,
        AuditEntry {
            org_id: auth.principal.org_id,
            actor_id: auth.principal.id,
            asserted_id: None,
            action: "auth.logout".into(),
            decision: AuditDecision::Allow,
            assurance: Some(auth.assurance()),
            reason: None,
            ip: None,
        },
    )
    .await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

// --- helpers ---

async fn passkeys_for(
    state: &AppState,
    principal_id: PrincipalId,
) -> ApiResult<Vec<PasskeyCredential>> {
    Ok(state
        .identity()
        .list_credentials(principal_id)
        .await?
        .into_iter()
        .map(|c| {
            let Credential::Passkey(pk) = c;
            pk
        })
        .collect())
}
