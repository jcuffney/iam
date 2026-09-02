//! Credential revocation — for a lost or stolen device.

use axum::Json;
use axum::extract::{Path, State};
use iam_core::{AdminAction, Assurance, AuditDecision, Permission};

use crate::audit::{self, AuditEntry};
use crate::error::ApiResult;
use crate::extract::Authenticated;
use crate::guard::require_permission;
use crate::routes::principals::{b64url, from_b64url};
use crate::state::AppState;

/// DELETE /credentials/{id} — revoke a passkey. The principal itself may do so
/// at cryptographic assurance (proving it still holds another credential), or
/// an admin may on its behalf.
///
/// `{id}` is the base64url-encoded raw credential id.
pub async fn delete(
    State(state): State<AppState>,
    auth: Authenticated,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_full_scope()?;
    let credential_id = from_b64url(&id)?;

    let credential = state.identity().get_credential(&credential_id).await?;
    let owner = credential.principal_id();

    let is_self_cryptographic = owner == auth.principal.id && auth.assurance() == Assurance::Cryptographic;
    if !is_self_cryptographic {
        require_permission(&state, &auth, Permission::Admin(AdminAction::ManagePrincipals), None).await?;
    }

    state.identity().delete_credential(&credential_id).await?;

    audit::record(
        &state,
        AuditEntry {
            org_id: auth.principal.org_id,
            actor_id: auth.principal.id,
            asserted_id: None,
            action: "credential.revoke".into(),
            decision: AuditDecision::Allow,
            assurance: Some(auth.assurance()),
            reason: Some(format!("credential {} of {}", b64url(&credential_id), owner)),
            ip: None,
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "revoked": id })))
}
