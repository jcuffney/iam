//! Audit as a first-class write path.
//!
//! Every security-relevant outcome flows through [`record`] — a real store
//! write, awaited before the response, not a `tracing` side effect. Delegated
//! requests always record both the acting principal and the asserted one.

use std::net::IpAddr;

use iam_core::{Assurance, AuditDecision, AuditEvent, OrgId, PrincipalId};
use time::OffsetDateTime;

use crate::state::AppState;

/// A single audit write. Kept small and explicit so call sites read clearly.
pub struct AuditEntry {
    pub org_id: OrgId,
    pub actor_id: PrincipalId,
    pub asserted_id: Option<PrincipalId>,
    pub action: String,
    pub decision: AuditDecision,
    pub assurance: Option<Assurance>,
    pub reason: Option<String>,
    pub ip: Option<IpAddr>,
}

/// Write an audit event. Failures to persist are logged but do not fail the
/// request that is already decided — the alternative (refusing a legitimate,
/// already-authorized action because the audit row could not be written) is
/// worse. This is the one place a store error is intentionally swallowed.
pub async fn record(state: &AppState, entry: AuditEntry) {
    let event = AuditEvent {
        org_id: entry.org_id,
        actor_id: entry.actor_id,
        asserted_id: entry.asserted_id,
        action: entry.action,
        decision: entry.decision,
        assurance: entry.assurance,
        reason: entry.reason,
        ip: entry.ip,
        occurred_at: OffsetDateTime::now_utc(),
    };
    if let Err(e) = state.audit().append(&event).await {
        tracing::error!(error = %e, action = %event.action, "failed to write audit event");
    }
}
