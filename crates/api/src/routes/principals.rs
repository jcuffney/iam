//! Principal lifecycle: creation (admin), inspection, role assignment,
//! disable/enable, and recovery-code reissue.

use axum::Json;
use axum::extract::{Path, State};
use iam_auth::{generate_recovery_codes, generate_registration_token, hash_code};
use iam_core::{
    AdminAction, AuditDecision, CredentialKind, Permission, Principal, PrincipalId, PrincipalKind,
};
use iam_store::CodePurpose;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::audit::{self, AuditEntry};
use crate::error::{ApiError, ApiResult};
use crate::extract::Authenticated;
use crate::guard::require_permission;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreatePrincipalRequest {
    pub kind: PrincipalKind,
    pub handle: String,
    pub display_name: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Serialize)]
pub struct CreatePrincipalResponse {
    pub principal: Principal,
    /// Shown exactly once. Store these somewhere safe.
    pub recovery_codes: Vec<String>,
    /// Single-use token required to register this principal's first credential.
    pub registration_token: String,
}

/// POST /principals — admin creates a credential-less principal and receives
/// its one-time recovery codes and registration token.
pub async fn create(
    State(state): State<AppState>,
    auth: Authenticated,
    Json(req): Json<CreatePrincipalRequest>,
) -> ApiResult<Json<CreatePrincipalResponse>> {
    auth.require_full_scope()?;
    require_permission(
        &state,
        &auth,
        Permission::Admin(AdminAction::ManagePrincipals),
        None,
    )
    .await?;

    let org_id = auth.principal.org_id;
    let principal = Principal {
        id: PrincipalId::new(),
        org_id,
        kind: req.kind,
        handle: req.handle,
        display_name: req.display_name,
        created_at: OffsetDateTime::now_utc(),
        disabled_at: None,
    };
    state.identity().create_principal(&principal).await?;

    // Assign requested roles (validated to exist in this org).
    for role_name in &req.roles {
        let role = state
            .identity()
            .get_role_by_name(org_id, role_name)
            .await
            .map_err(|_| ApiError::BadRequest(format!("unknown role: {role_name}")))?;
        state.identity().assign_role(principal.id, role.id).await?;
    }

    // Recovery codes and a registration token, hashed at rest, shown once.
    let recovery_codes = generate_recovery_codes();
    let recovery_hashes = hash_all(&recovery_codes)?;
    state
        .identity()
        .insert_codes(principal.id, CodePurpose::Recovery, &recovery_hashes)
        .await?;

    let registration_token = generate_registration_token();
    let token_hash = hash_code(&registration_token).map_err(|e| ApiError::Internal(e.into()))?;
    state
        .identity()
        .insert_codes(principal.id, CodePurpose::Registration, &[token_hash])
        .await?;

    audit::record(
        &state,
        AuditEntry {
            org_id,
            actor_id: auth.principal.id,
            asserted_id: None,
            action: "principal.create".into(),
            decision: AuditDecision::Allow,
            assurance: Some(auth.assurance()),
            reason: Some(format!("created {}", principal.id)),
            ip: None,
        },
    )
    .await;

    Ok(Json(CreatePrincipalResponse {
        principal,
        recovery_codes,
        registration_token,
    }))
}

#[derive(Serialize)]
pub struct CredentialView {
    pub credential_id: String,
    pub kind: CredentialKind,
    pub nickname: Option<String>,
    pub sign_count: u32,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<OffsetDateTime>,
}

#[derive(Serialize)]
pub struct PrincipalView {
    pub principal: Principal,
    pub roles: Vec<String>,
    pub credentials: Vec<CredentialView>,
}

/// GET /principals/{id} — self or an admin may view a principal with its
/// credentials (metadata only) and roles.
pub async fn get(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(id): Path<String>,
) -> ApiResult<Json<PrincipalView>> {
    auth.require_full_scope()?;
    let principal_id = parse_principal_id(&id)?;

    if principal_id != auth.principal.id {
        require_permission(
            &state,
            &auth,
            Permission::Admin(AdminAction::ManagePrincipals),
            None,
        )
        .await?;
    }

    let principal = state.identity().get_principal(principal_id).await?;
    let roles = state
        .identity()
        .roles_for_principal(principal_id)
        .await?
        .into_iter()
        .map(|r| r.name)
        .collect();
    let credentials = state
        .identity()
        .list_credentials(principal_id)
        .await?
        .into_iter()
        .map(|c| {
            let iam_core::Credential::Passkey(pk) = c;
            CredentialView {
                credential_id: b64url(&pk.credential_id),
                kind: CredentialKind::Passkey,
                nickname: pk.nickname,
                sign_count: pk.sign_count,
                last_used_at: pk.last_used_at,
            }
        })
        .collect();

    Ok(Json(PrincipalView {
        principal,
        roles,
        credentials,
    }))
}

/// PUT /principals/{id}/roles/{role} — assign a role (admin:manage_roles).
pub async fn assign_role(
    State(state): State<AppState>,
    auth: Authenticated,
    Path((id, role_name)): Path<(String, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_full_scope()?;
    require_permission(
        &state,
        &auth,
        Permission::Admin(AdminAction::ManageRoles),
        None,
    )
    .await?;
    let principal_id = parse_principal_id(&id)?;

    let target = state.identity().get_principal(principal_id).await?;
    let role = state
        .identity()
        .get_role_by_name(target.org_id, &role_name)
        .await
        .map_err(|_| ApiError::BadRequest(format!("unknown role: {role_name}")))?;
    state.identity().assign_role(principal_id, role.id).await?;

    audit_role_change(&state, &auth, principal_id, &role_name, "role.assign").await;
    Ok(Json(serde_json::json!({ "assigned": role_name })))
}

/// DELETE /principals/{id}/roles/{role} — revoke a role (admin:manage_roles).
pub async fn revoke_role(
    State(state): State<AppState>,
    auth: Authenticated,
    Path((id, role_name)): Path<(String, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_full_scope()?;
    require_permission(
        &state,
        &auth,
        Permission::Admin(AdminAction::ManageRoles),
        None,
    )
    .await?;
    let principal_id = parse_principal_id(&id)?;

    let target = state.identity().get_principal(principal_id).await?;
    let role = state
        .identity()
        .get_role_by_name(target.org_id, &role_name)
        .await
        .map_err(|_| ApiError::BadRequest(format!("unknown role: {role_name}")))?;
    state.identity().revoke_role(principal_id, role.id).await?;

    audit_role_change(&state, &auth, principal_id, &role_name, "role.revoke").await;
    Ok(Json(serde_json::json!({ "revoked": role_name })))
}

/// POST /principals/{id}/disable (admin:manage_principals). Live sessions are
/// neutralized immediately because the extractor rejects disabled principals.
pub async fn disable(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    set_disabled(
        &state,
        &auth,
        &id,
        Some(OffsetDateTime::now_utc()),
        "principal.disable",
    )
    .await
}

/// POST /principals/{id}/enable (admin:manage_principals).
pub async fn enable(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    set_disabled(&state, &auth, &id, None, "principal.enable").await
}

#[derive(Serialize)]
pub struct ReissueResponse {
    pub recovery_codes: Vec<String>,
}

/// POST /principals/{id}/recovery-codes — an admin, or the principal itself at
/// cryptographic assurance, burns unused recovery codes and gets a fresh set.
pub async fn reissue_recovery_codes(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(id): Path<String>,
) -> ApiResult<Json<ReissueResponse>> {
    auth.require_full_scope()?;
    let principal_id = parse_principal_id(&id)?;

    let is_self_cryptographic =
        principal_id == auth.principal.id && auth.assurance() == iam_core::Assurance::Cryptographic;
    if !is_self_cryptographic {
        require_permission(
            &state,
            &auth,
            Permission::Admin(AdminAction::ManagePrincipals),
            None,
        )
        .await?;
    }

    state
        .identity()
        .delete_unused_codes(principal_id, CodePurpose::Recovery)
        .await?;
    let recovery_codes = generate_recovery_codes();
    let hashes = hash_all(&recovery_codes)?;
    state
        .identity()
        .insert_codes(principal_id, CodePurpose::Recovery, &hashes)
        .await?;

    audit::record(
        &state,
        AuditEntry {
            org_id: auth.principal.org_id,
            actor_id: auth.principal.id,
            asserted_id: None,
            action: "recovery.reissue".into(),
            decision: AuditDecision::Allow,
            assurance: Some(auth.assurance()),
            reason: Some(format!("for {principal_id}")),
            ip: None,
        },
    )
    .await;

    Ok(Json(ReissueResponse { recovery_codes }))
}

// --- helpers ---

async fn set_disabled(
    state: &AppState,
    auth: &Authenticated,
    id: &str,
    disabled_at: Option<OffsetDateTime>,
    action: &str,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_full_scope()?;
    require_permission(
        state,
        auth,
        Permission::Admin(AdminAction::ManagePrincipals),
        None,
    )
    .await?;
    let principal_id = parse_principal_id(id)?;
    state
        .identity()
        .set_principal_disabled(principal_id, disabled_at)
        .await?;

    audit::record(
        state,
        AuditEntry {
            org_id: auth.principal.org_id,
            actor_id: auth.principal.id,
            asserted_id: None,
            action: action.to_string(),
            decision: AuditDecision::Allow,
            assurance: Some(auth.assurance()),
            reason: Some(format!("target {principal_id}")),
            ip: None,
        },
    )
    .await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn audit_role_change(
    state: &AppState,
    auth: &Authenticated,
    target: PrincipalId,
    role: &str,
    action: &str,
) {
    audit::record(
        state,
        AuditEntry {
            org_id: auth.principal.org_id,
            actor_id: auth.principal.id,
            asserted_id: None,
            action: action.to_string(),
            decision: AuditDecision::Allow,
            assurance: Some(auth.assurance()),
            reason: Some(format!("{role} on {target}")),
            ip: None,
        },
    )
    .await;
}

fn hash_all(codes: &[String]) -> ApiResult<Vec<String>> {
    codes
        .iter()
        .map(|c| hash_code(c).map_err(|e| ApiError::Internal(e.into())))
        .collect()
}

pub(crate) fn parse_principal_id(s: &str) -> ApiResult<PrincipalId> {
    s.parse()
        .map_err(|_| ApiError::BadRequest("invalid principal id".into()))
}

pub(crate) fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn from_b64url(s: &str) -> ApiResult<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| ApiError::BadRequest("invalid base64url".into()))
}
