//! The authorization decision endpoint — where the delegation rule, the
//! assurance ladder, and capability grants all resolve through `iam_policy`.

use axum::Json;
use axum::extract::State;
use iam_core::{
    Assurance, AuditDecision, CapabilityAction, CapabilityRef, Permission, PermissionSet,
    Principal, PrincipalId,
};
use iam_policy::{
    CapabilityContext, Decision, Reason, authorize as policy_authorize,
    authorize_capability_invocation,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::audit::{self, AuditEntry};
use crate::error::{ApiError, ApiResult};
use crate::extract::Authenticated;
use crate::ip::ClientIp;
use crate::metrics;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct AuthorizeRequest {
    /// When present, the acting principal (the token holder, e.g. a device) is
    /// asserting this human's identity. The decision is made at `Asserted`
    /// assurance over the intersection of both permission sets.
    pub asserted_principal: Option<PrincipalId>,
    /// The permission being requested, e.g. `memory:read:private` or
    /// `capability:invoke`.
    pub action: Permission,
    /// Required when `action` is `capability:invoke`: which capability.
    pub capability: Option<CapabilityRef>,
}

#[derive(Serialize)]
pub struct AuthorizeResponse {
    pub allowed: bool,
    pub assurance: Assurance,
    pub reason: String,
    /// The acting principal.
    pub actor: PrincipalId,
    pub asserted_principal: Option<PrincipalId>,
}

/// POST /authorize — resolve a permission (optionally delegated) or a capability
/// invocation. Always audits both identities.
pub async fn authorize(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: Authenticated,
    Json(req): Json<AuthorizeRequest>,
) -> ApiResult<Json<AuthorizeResponse>> {
    auth.require_full_scope()?;
    let actor = &auth.principal;
    let now = OffsetDateTime::now_utc();

    // Resolve the asserted principal (if any) and enforce the org boundary
    // BEFORE any policy runs: a device may only ever assert an identity within
    // its own org.
    let asserted: Option<Principal> = match req.asserted_principal {
        Some(id) => {
            let p = state.identity().get_principal(id).await?;
            if p.org_id != actor.org_id {
                return Ok(cross_org_denied(&state, actor, &p, &req, ip).await);
            }
            Some(p)
        }
        None => None,
    };

    // Assurance: a device vouching for a human is `Asserted`; acting as oneself
    // carries the session's assurance (Cryptographic after a passkey login).
    let assurance = if asserted.is_some() {
        Assurance::Asserted
    } else {
        auth.assurance()
    };

    let actor_perms = state.identity().permissions_for_principal(actor.id).await?;
    let asserted_perms: Option<PermissionSet> = match &asserted {
        Some(p) => Some(state.identity().permissions_for_principal(p.id).await?),
        None => None,
    };

    // Dispatch: capability invocation vs plain permission.
    let decision = if matches!(req.action, Permission::Capability(CapabilityAction::Invoke)) {
        let capability = req.capability.clone().ok_or_else(|| {
            ApiError::BadRequest("capability required for capability:invoke".into())
        })?;
        // The grant is evaluated for the EFFECTIVE principal — the asserted
        // human when delegated, otherwise the actor.
        let effective = asserted.as_ref().map(|p| p.id).unwrap_or(actor.id);
        let found = state
            .connections()
            .find_grant_for_authorization(effective, &capability)
            .await?;
        let (grant, connection_active) = match &found {
            Some(g) => (Some(&g.grant), g.connection_active),
            None => (None, false),
        };
        authorize_capability_invocation(
            &actor_perms,
            asserted_perms.as_ref(),
            assurance,
            &capability,
            CapabilityContext {
                grant,
                connection_active,
                now,
                spend: state.spend_ledger(),
                invocations: state.invocation_ledger(),
            },
        )
    } else {
        policy_authorize(&actor_perms, asserted_perms.as_ref(), assurance, req.action)
    };

    record_and_respond(&state, actor, asserted.as_ref(), &req, &decision, ip).await
}

/// Build the response, audit both identities, and bump metrics.
async fn record_and_respond(
    state: &AppState,
    actor: &Principal,
    asserted: Option<&Principal>,
    req: &AuthorizeRequest,
    decision: &Decision,
    ip: Option<std::net::IpAddr>,
) -> ApiResult<Json<AuthorizeResponse>> {
    let audit_decision = if decision.allowed {
        AuditDecision::Allow
    } else {
        AuditDecision::Deny
    };
    metrics::authorize_decision(
        if decision.allowed { "allow" } else { "deny" },
        decision.reason.code(),
    );

    audit::record(
        state,
        AuditEntry {
            org_id: actor.org_id,
            actor_id: actor.id,
            asserted_id: asserted.map(|p| p.id),
            action: action_label(req),
            decision: audit_decision,
            assurance: Some(decision.assurance),
            reason: Some(reason_detail(&decision.reason)),
            ip,
        },
    )
    .await;

    Ok(Json(AuthorizeResponse {
        allowed: decision.allowed,
        assurance: decision.assurance,
        reason: decision.reason.code().to_string(),
        actor: actor.id,
        asserted_principal: asserted.map(|p| p.id),
    }))
}

/// A cross-org assertion is denied before policy and audited as such.
async fn cross_org_denied(
    state: &AppState,
    actor: &Principal,
    asserted: &Principal,
    req: &AuthorizeRequest,
    ip: Option<std::net::IpAddr>,
) -> Json<AuthorizeResponse> {
    metrics::authorize_decision("deny", "cross_org_assertion");
    audit::record(
        state,
        AuditEntry {
            org_id: actor.org_id,
            actor_id: actor.id,
            asserted_id: Some(asserted.id),
            action: action_label(req),
            decision: AuditDecision::Deny,
            assurance: Some(Assurance::Asserted),
            reason: Some("cross_org_assertion".into()),
            ip,
        },
    )
    .await;
    Json(AuthorizeResponse {
        allowed: false,
        assurance: Assurance::Asserted,
        reason: "cross_org_assertion".into(),
        actor: actor.id,
        asserted_principal: Some(asserted.id),
    })
}

fn action_label(req: &AuthorizeRequest) -> String {
    match &req.capability {
        Some(cap) if matches!(req.action, Permission::Capability(CapabilityAction::Invoke)) => {
            format!("capability:invoke:{}", cap.operation)
        }
        _ => req.action.to_string(),
    }
}

fn reason_detail(reason: &Reason) -> String {
    match reason {
        Reason::InsufficientAssurance { required } => {
            format!("insufficient_assurance:requires_{required}")
        }
        Reason::ConstraintViolated { constraint } => format!("constraint_violated:{constraint}"),
        other => other.code().to_string(),
    }
}
