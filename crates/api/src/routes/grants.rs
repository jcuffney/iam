//! Capability grants: the object-capability bindings policy evaluates.
//!
//! Creating or revoking a grant is `connection:manage` (cryptographic), so a
//! delegated device may invoke a granted capability but never mint or revoke a
//! grant — that falls straight out of the assurance ladder, no special-casing.

use axum::Json;
use axum::extract::{Path, State};
use iam_core::{
    AuditDecision, CapabilityRef, Connection, ConnectionAction, Constraint, Grant, GrantId,
    Permission, PrincipalId,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::audit::{self, AuditEntry};
use crate::error::{ApiError, ApiResult};
use crate::extract::Authenticated;
use crate::guard::require_permission;
use crate::ip::ClientIp;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreateGrantRequest {
    /// The grantee principal.
    pub principal_id: PrincipalId,
    pub capability: CapabilityRef,
    #[serde(default)]
    pub constraints: Vec<Constraint>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Serialize)]
pub struct GrantView {
    pub id: GrantId,
    pub principal_id: PrincipalId,
    pub capability: CapabilityRef,
    pub granted_by: PrincipalId,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

/// POST /grants — grant a principal the right to invoke a capability.
pub async fn create(
    State(state): State<AppState>,
    auth: Authenticated,
    ClientIp(ip): ClientIp,
    Json(req): Json<CreateGrantRequest>,
) -> ApiResult<Json<GrantView>> {
    auth.require_full_scope()?;
    require_permission(
        &state,
        &auth,
        Permission::Connection(ConnectionAction::Manage),
        None,
    )
    .await?;

    // The actor must own the connection being granted over.
    let connection = state
        .connections()
        .get_connection(req.capability.connection_id)
        .await?;
    ensure_owner(&connection, &auth)?;

    // The grantee must be a real principal in the actor's org.
    let grantee = state.identity().get_principal(req.principal_id).await?;
    if grantee.org_id != auth.principal.org_id {
        return Err(ApiError::BadRequest("grantee is in a different org".into()));
    }

    // The operation must be one the connection actually declared (this also
    // enforces "opaque connections are grantable only as a whole", since an
    // opaque connection declares only `*`).
    let declared = state
        .connections()
        .list_capabilities(req.capability.connection_id)
        .await?;
    if !declared
        .iter()
        .any(|c| c.operation == req.capability.operation)
    {
        return Err(ApiError::BadRequest(format!(
            "capability {} is not declared on this connection",
            req.capability.operation
        )));
    }

    // Reject constraints that are not yet enforced. `iam-policy` evaluates Spend
    // and RateLimit against the SpendLedger/InvocationLedger seam
    // (crates/policy/src/ledger.rs), but nothing records usage into those
    // ledgers yet (there is no invocation-report path), so accepting such a
    // constraint would advertise a cap that enforces nothing. Only TimeWindow
    // (stateless, computed from the clock) is honored today.
    for constraint in &req.constraints {
        match constraint {
            Constraint::TimeWindow { .. } => {}
            Constraint::Spend { .. } | Constraint::RateLimit { .. } => {
                return Err(ApiError::BadRequest(
                    "spend and rate-limit constraints are not yet enforced; only time_window is supported".into(),
                ));
            }
        }
    }

    let grant = Grant {
        id: GrantId::new(),
        principal: req.principal_id,
        capability: req.capability.clone(),
        constraints: req.constraints,
        expires_at: req.expires_at,
        granted_by: auth.principal.id,
        created_at: OffsetDateTime::now_utc(),
        revoked_at: None,
    };
    state.connections().create_grant(&grant).await?;

    audit::record(
        &state,
        AuditEntry {
            org_id: auth.principal.org_id,
            actor_id: auth.principal.id,
            asserted_id: None,
            action: "grant.create".into(),
            decision: AuditDecision::Allow,
            assurance: Some(auth.assurance()),
            reason: Some(format!("grant {} to {}", grant.id, grant.principal)),
            ip,
        },
    )
    .await;

    Ok(Json(GrantView {
        id: grant.id,
        principal_id: grant.principal,
        capability: grant.capability,
        granted_by: grant.granted_by,
        expires_at: grant.expires_at,
    }))
}

/// DELETE /grants/{id} — revoke a grant (connection:manage).
pub async fn revoke(
    State(state): State<AppState>,
    auth: Authenticated,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    auth.require_full_scope()?;
    require_permission(
        &state,
        &auth,
        Permission::Connection(ConnectionAction::Manage),
        None,
    )
    .await?;
    let grant_id = GrantId(
        id.parse()
            .map_err(|_| ApiError::BadRequest("invalid grant id".into()))?,
    );

    // Must own the connection the grant is over.
    let grant = state.connections().get_grant(grant_id).await?;
    let connection = state
        .connections()
        .get_connection(grant.capability.connection_id)
        .await?;
    ensure_owner(&connection, &auth)?;

    state
        .connections()
        .revoke_grant(grant_id, OffsetDateTime::now_utc())
        .await?;

    audit::record(
        &state,
        AuditEntry {
            org_id: auth.principal.org_id,
            actor_id: auth.principal.id,
            asserted_id: None,
            action: "grant.revoke".into(),
            decision: AuditDecision::Allow,
            assurance: Some(auth.assurance()),
            reason: Some(format!("grant {grant_id}")),
            ip,
        },
    )
    .await;

    Ok(Json(serde_json::json!({ "revoked": grant_id })))
}

fn ensure_owner(connection: &Connection, auth: &Authenticated) -> ApiResult<()> {
    if connection.principal_id != auth.principal.id {
        return Err(ApiError::Forbidden(
            "not the owner of this connection".into(),
        ));
    }
    Ok(())
}
