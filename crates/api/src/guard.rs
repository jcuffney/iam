//! Permission guards for handlers.
//!
//! A guard resolves the acting principal's permissions and runs the same
//! `iam_policy::authorize` everything else uses (no delegation — the principal
//! is acting as itself). A denial is audited here and turned into 403; on allow
//! the handler proceeds and audits the concrete action it performs.

use std::net::IpAddr;

use iam_core::{AuditDecision, Permission};
use iam_policy::authorize;

use crate::audit::{self, AuditEntry};
use crate::error::{ApiError, ApiResult};
use crate::extract::Authenticated;
use crate::state::AppState;

/// Require that the authenticated principal holds `permission` at its session's
/// assurance. Audits and returns `Forbidden` on denial.
pub async fn require_permission(
    state: &AppState,
    auth: &Authenticated,
    permission: Permission,
    ip: Option<IpAddr>,
) -> ApiResult<()> {
    let perms = state
        .identity()
        .permissions_for_principal(auth.principal.id)
        .await?;
    let decision = authorize(&perms, None, auth.assurance(), permission);

    if !decision.allowed {
        audit::record(
            state,
            AuditEntry {
                org_id: auth.principal.org_id,
                actor_id: auth.principal.id,
                asserted_id: None,
                action: permission.to_string(),
                decision: AuditDecision::Deny,
                assurance: Some(auth.assurance()),
                reason: Some(decision.reason.code().to_string()),
                ip,
            },
        )
        .await;
        return Err(ApiError::Forbidden(format!(
            "{} denied ({})",
            permission,
            decision.reason.code()
        )));
    }
    Ok(())
}
