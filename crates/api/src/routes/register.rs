//! WebAuthn registration: first-credential bootstrap, adding a device to an
//! existing principal, and the shared (idempotent) finish.

use axum::Json;
use axum::extract::State;
use iam_auth::ceremony::{CreationChallengeResponse, RegisterPublicKeyCredential};
use iam_auth::verify_code;
use iam_core::{AuditDecision, PrincipalId};
use iam_store::{ChallengeMode, ChallengeRecord, CodePurpose};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::audit::{self, AuditEntry};
use crate::error::{ApiError, ApiResult};
use crate::extract::Authenticated;
use crate::ip::ClientIp;
use crate::ratelimit::enforce_principal;
use crate::routes::principals::b64url;
use crate::state::AppState;

/// How long a ceremony challenge stays valid.
const CHALLENGE_TTL: Duration = Duration::minutes(5);

#[derive(Deserialize)]
pub struct RegisterStartRequest {
    /// Org slug — handles are unique per org, so the org must be named to
    /// resolve the principal.
    pub org_slug: String,
    pub handle: String,
    /// Single-use token issued by `POST /principals`. Without it a stranger who
    /// guesses a handle could claim a credential-less principal.
    pub registration_token: String,
}

#[derive(Serialize)]
pub struct RegisterStartResponse {
    pub challenge_id: String,
    /// The `PublicKeyCredentialCreationOptions` the browser passes to
    /// `navigator.credentials.create`.
    #[serde(rename = "publicKey")]
    pub public_key: CreationChallengeResponse,
}

/// POST /register/start — begin binding the FIRST credential to an existing,
/// credential-less principal, gated by its single-use registration token.
pub async fn start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<RegisterStartRequest>,
) -> ApiResult<Json<RegisterStartResponse>> {
    let org = state
        .identity()
        .get_org_by_slug(&req.org_slug)
        .await
        .map_err(|_| ApiError::Unauthorized("registration failed".into()))?;
    let principal = state
        .identity()
        .get_principal_by_handle(org.id, &req.handle)
        .await
        .map_err(|_| ApiError::Unauthorized("registration failed".into()))?;

    enforce_principal(&state, principal.id.0)?;

    // Verify and CONSUME a matching registration token (single use).
    consume_one_time_code(
        &state,
        principal.id,
        CodePurpose::Registration,
        &req.registration_token,
    )
    .await
    .map_err(|_| {
        // Uniform error; do not reveal whether the handle or the token was
        // the problem.
        ApiError::Unauthorized("registration failed".into())
    })?;

    let existing = existing_credential_ids(&state, principal.id).await?;
    let (ccr, state_blob) = state.webauthn().start_registration(
        principal.id.0,
        &principal.handle,
        &principal.display_name,
        &existing,
    )?;

    let challenge_id = Uuid::new_v4().to_string();
    state
        .challenges()
        .put_challenge(&ChallengeRecord {
            challenge_id: challenge_id.clone(),
            mode: ChallengeMode::RegisterFirst,
            principal_id: principal.id,
            org_id: org.id,
            state_blob,
            expires_at: OffsetDateTime::now_utc() + CHALLENGE_TTL,
        })
        .await?;

    audit::record(
        &state,
        AuditEntry {
            org_id: org.id,
            actor_id: principal.id,
            asserted_id: None,
            action: "register.start".into(),
            decision: AuditDecision::Allow,
            assurance: None,
            reason: Some("first credential".into()),
            ip,
        },
    )
    .await;

    Ok(Json(RegisterStartResponse {
        challenge_id,
        public_key: ccr,
    }))
}

/// POST /register/device/start — add another credential to the authenticated
/// principal. Requires a valid session (full OR recovery-scoped), so the new
/// passkey attaches to the SAME principal instead of creating a new account.
///
/// The credential's nickname is supplied later, at finish.
pub async fn device_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: Authenticated,
) -> ApiResult<Json<RegisterStartResponse>> {
    // Note: no require_full_scope — a recovery session exists precisely to add a
    // device.
    enforce_principal(&state, auth.principal.id.0)?;

    let existing = existing_credential_ids(&state, auth.principal.id).await?;
    let (ccr, state_blob) = state.webauthn().start_registration(
        auth.principal.id.0,
        &auth.principal.handle,
        &auth.principal.display_name,
        &existing,
    )?;

    let challenge_id = Uuid::new_v4().to_string();
    state
        .challenges()
        .put_challenge(&ChallengeRecord {
            challenge_id: challenge_id.clone(),
            mode: ChallengeMode::RegisterDevice,
            principal_id: auth.principal.id,
            org_id: auth.principal.org_id,
            state_blob,
            expires_at: OffsetDateTime::now_utc() + CHALLENGE_TTL,
        })
        .await?;

    audit::record(
        &state,
        AuditEntry {
            org_id: auth.principal.org_id,
            actor_id: auth.principal.id,
            asserted_id: None,
            action: "register.device_start".into(),
            decision: AuditDecision::Allow,
            assurance: Some(auth.assurance()),
            reason: Some("add credential".into()),
            ip,
        },
    )
    .await;

    Ok(Json(RegisterStartResponse {
        challenge_id,
        public_key: ccr,
    }))
}

#[derive(Deserialize)]
pub struct RegisterFinishRequest {
    pub challenge_id: String,
    pub credential: RegisterPublicKeyCredential,
    pub nickname: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterFinishResponse {
    pub principal_id: PrincipalId,
    pub credential_id: String,
    /// True when this call actually created the credential; false when a retry
    /// found it already present (idempotent).
    pub created: bool,
}

/// POST /register/finish — verify the attestation and persist the credential.
///
/// Idempotent: a retried finish whose challenge was already consumed looks the
/// credential up by its raw id and returns the original success rather than
/// erroring or duplicating.
pub async fn finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<RegisterFinishRequest>,
) -> ApiResult<Json<RegisterFinishResponse>> {
    let now = OffsetDateTime::now_utc();
    let raw_id = req.credential.raw_id.as_ref().to_vec();

    let challenge = state
        .challenges()
        .take_challenge(&req.challenge_id, now)
        .await?;

    let Some(challenge) = challenge else {
        // Challenge gone: either expired, or this is a retry after a successful
        // finish. Treat a known credential as the idempotent success case.
        if let Ok(existing) = state.get_credential_owner(&raw_id).await {
            return Ok(Json(RegisterFinishResponse {
                principal_id: existing,
                credential_id: b64url(&raw_id),
                created: false,
            }));
        }
        return Err(ApiError::BadRequest("unknown or expired challenge".into()));
    };

    let registered = state.webauthn().finish_registration(
        challenge.principal_id,
        &req.credential,
        &challenge.state_blob,
        req.nickname,
    )?;

    let credential = iam_core::Credential::Passkey(registered.credential);
    let created = state.identity().insert_credential(&credential).await?;

    audit::record(
        &state,
        AuditEntry {
            org_id: challenge.org_id,
            actor_id: challenge.principal_id,
            asserted_id: None,
            action: "register.finish".into(),
            decision: AuditDecision::Allow,
            assurance: None,
            reason: Some(
                if created {
                    "credential registered"
                } else {
                    "idempotent retry"
                }
                .into(),
            ),
            ip,
        },
    )
    .await;

    Ok(Json(RegisterFinishResponse {
        principal_id: challenge.principal_id,
        credential_id: b64url(&registered.credential_id),
        created,
    }))
}

// --- helpers ---

async fn existing_credential_ids(
    state: &AppState,
    principal_id: PrincipalId,
) -> ApiResult<Vec<Vec<u8>>> {
    Ok(state
        .identity()
        .list_credentials(principal_id)
        .await?
        .iter()
        .map(|c| c.credential_id().to_vec())
        .collect())
}

/// Verify a presented one-time code against the principal's unused codes and
/// atomically consume the match. Errors if none match.
pub(crate) async fn consume_one_time_code(
    state: &AppState,
    principal_id: PrincipalId,
    purpose: CodePurpose,
    presented: &str,
) -> ApiResult<()> {
    let candidates = state
        .identity()
        .list_unused_codes(principal_id, purpose)
        .await?;
    for candidate in candidates {
        if verify_code(presented, &candidate.code_hash) {
            // Race-safe single use: only the first caller to flip used_at wins.
            if state.identity().mark_code_used(candidate.id).await? {
                return Ok(());
            }
        }
    }
    Err(ApiError::Unauthorized("invalid code".into()))
}

// Small convenience on AppState to look up a credential's owning principal.
impl AppState {
    pub(crate) async fn get_credential_owner(&self, raw_id: &[u8]) -> ApiResult<PrincipalId> {
        Ok(self.identity().get_credential(raw_id).await?.principal_id())
    }
}
