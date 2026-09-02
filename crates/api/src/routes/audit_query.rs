//! Filterable audit query (admin:read_audit).

use axum::Json;
use axum::extract::{Query, State};
use iam_core::{AdminAction, AuditDecision, AuditEvent, Permission, PrincipalId};
use iam_store::AuditFilter;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::error::ApiResult;
use crate::extract::Authenticated;
use crate::guard::require_permission;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct AuditQuery {
    pub actor_id: Option<PrincipalId>,
    pub action: Option<String>,
    pub decision: Option<AuditDecision>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub to: Option<OffsetDateTime>,
    pub limit: Option<i64>,
}

/// GET /audit — query the audit trail within the caller's org.
pub async fn query(
    State(state): State<AppState>,
    auth: Authenticated,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Vec<AuditEvent>>> {
    auth.require_full_scope()?;
    require_permission(
        &state,
        &auth,
        Permission::Admin(AdminAction::ReadAudit),
        None,
    )
    .await?;

    let filter = AuditFilter {
        // Scope every query to the caller's org — an admin cannot read another
        // tenant's trail.
        org_id: Some(auth.principal.org_id),
        actor_id: q.actor_id,
        action: q.action,
        decision: q.decision,
        from: q.from,
        to: q.to,
        limit: q.limit.unwrap_or(100).clamp(1, 1000),
    };

    let events = state.audit().query(&filter).await?;
    Ok(Json(events))
}
