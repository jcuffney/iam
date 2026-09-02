//! Pure authorization logic.
//!
//! Every function here takes already-loaded data and returns a [`Decision`].
//! No IO, no store handles, no clock of its own (time is passed in). That makes
//! the delegation rule and the assurance ladder — the security-critical core of
//! the service — trivially testable, and the tests below cover them
//! exhaustively.
//!
//! The delegation rule: a device may act on behalf of a human, but never
//! exceeds its own ceiling. The effective permission set is the **intersection**
//! of the device's permissions and the asserted human's permissions — never the
//! union.

pub mod ledger;

use iam_core::{Assurance, CapabilityRef, Constraint, Grant, Permission, PermissionSet, SpendPeriod};
use time::OffsetDateTime;

pub use ledger::{InMemoryInvocationLedger, InMemorySpendLedger, InvocationLedger, SpendLedger};

/// The outcome of an authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    /// The assurance level under which the decision was made — echoed back so
    /// the caller records what actually gated the request.
    pub assurance: Assurance,
    pub reason: Reason,
}

/// Why a decision came out the way it did. Distinguishing the denial reasons
/// matters for the audit trail and for debugging a delegation that unexpectedly
/// fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    Allowed,
    /// The authenticated principal (the actor, e.g. the device) lacks the
    /// permission outright.
    NotPermittedForActor,
    /// The actor has it, but the asserted principal does not — so the
    /// intersection excludes it.
    NotPermittedForAsserted,
    /// The permission is held, but the request's assurance is below the
    /// minimum the permission requires.
    InsufficientAssurance { required: Assurance },
    /// Capability-invocation only: no live grant for this principal and
    /// capability.
    NoGrant,
    /// Capability-invocation only: the grant exists but is revoked.
    GrantRevoked,
    /// Capability-invocation only: the grant's expiry has passed.
    GrantExpired,
    /// Capability-invocation only: the connection behind the grant is revoked
    /// or expired.
    ConnectionInactive,
    /// Capability-invocation only: a constraint on the grant was violated.
    ConstraintViolated { constraint: &'static str },
}

impl Reason {
    /// A short stable code for the audit trail.
    pub fn code(&self) -> &'static str {
        match self {
            Reason::Allowed => "allowed",
            Reason::NotPermittedForActor => "not_permitted_for_actor",
            Reason::NotPermittedForAsserted => "not_permitted_for_asserted",
            Reason::InsufficientAssurance { .. } => "insufficient_assurance",
            Reason::NoGrant => "no_grant",
            Reason::GrantRevoked => "grant_revoked",
            Reason::GrantExpired => "grant_expired",
            Reason::ConnectionInactive => "connection_inactive",
            Reason::ConstraintViolated { .. } => "constraint_violated",
        }
    }
}

/// Resolve the effective permission set for a request.
///
/// With no delegation this is just the actor's own set. With delegation it is
/// the **intersection** of the actor's set and the asserted principal's set:
/// the device can never let the human do something the device itself cannot,
/// and the human's assertion can never let the device do something the human
/// cannot. Neither party's ceiling is exceeded.
pub fn effective_permissions(actor_perms: &PermissionSet, asserted_perms: Option<&PermissionSet>) -> PermissionSet {
    match asserted_perms {
        Some(asserted) => actor_perms.intersection(asserted).copied().collect(),
        None => actor_perms.clone(),
    }
}

/// Authorize a plain permission request.
///
/// `assurance` is derived by the caller: `Cryptographic` when the acting
/// principal's own credential signed the request, `Asserted` when a device
/// vouched for the identity.
pub fn authorize(
    actor_perms: &PermissionSet,
    asserted_perms: Option<&PermissionSet>,
    assurance: Assurance,
    requested: Permission,
) -> Decision {
    // 1. Membership in the effective (intersected) set.
    let actor_has = actor_perms.contains(&requested);
    let asserted_has = asserted_perms.is_none_or(|a| a.contains(&requested));

    if !actor_has {
        return Decision { allowed: false, assurance, reason: Reason::NotPermittedForActor };
    }
    if !asserted_has {
        return Decision { allowed: false, assurance, reason: Reason::NotPermittedForAsserted };
    }

    // 2. Assurance ladder: the request must meet the permission's floor.
    let required = requested.required_assurance();
    if assurance < required {
        return Decision {
            allowed: false,
            assurance,
            reason: Reason::InsufficientAssurance { required },
        };
    }

    Decision { allowed: true, assurance, reason: Reason::Allowed }
}

/// Inputs for a capability-invocation decision, gathered by the caller from the
/// (store-isolated) connections store and the ledgers.
pub struct CapabilityContext<'a> {
    /// The grant for the effective principal and this capability, if one was
    /// found. The effective principal is the asserted human when delegated,
    /// otherwise the actor.
    pub grant: Option<&'a Grant>,
    /// Whether the connection behind the grant is currently active
    /// (unrevoked and unexpired).
    pub connection_active: bool,
    pub now: OffsetDateTime,
    pub spend: &'a dyn SpendLedger,
    pub invocations: &'a dyn InvocationLedger,
}

/// Authorize invoking a granted capability.
///
/// This goes through the *same* base [`authorize`] check as everything else —
/// `capability:invoke` is an ordinary permission subject to the intersection
/// rule and the assurance ladder — and then layers the object-capability
/// checks: a live grant must exist, its connection must be active, and every
/// constraint (including spend, checked against the ledger *before* allowing)
/// must hold.
pub fn authorize_capability_invocation(
    actor_perms: &PermissionSet,
    asserted_perms: Option<&PermissionSet>,
    assurance: Assurance,
    effective_principal_capability: &CapabilityRef,
    ctx: CapabilityContext<'_>,
) -> Decision {
    // Base permission gate first — no special path for capabilities.
    let base = authorize(actor_perms, asserted_perms, assurance, Permission::Capability(iam_core::CapabilityAction::Invoke));
    if !base.allowed {
        return base;
    }

    // A grant must exist and be live.
    let grant = match ctx.grant {
        Some(g) => g,
        None => return Decision { allowed: false, assurance, reason: Reason::NoGrant },
    };
    if grant.is_revoked() {
        return Decision { allowed: false, assurance, reason: Reason::GrantRevoked };
    }
    if grant.is_expired(ctx.now) {
        return Decision { allowed: false, assurance, reason: Reason::GrantExpired };
    }
    if !ctx.connection_active {
        return Decision { allowed: false, assurance, reason: Reason::ConnectionInactive };
    }

    // Every constraint must hold. Spend and rate are checked against the
    // ledgers *before* the invocation is authorized.
    for constraint in &grant.constraints {
        if let Some(violated) = check_constraint(constraint, grant, effective_principal_capability, &ctx) {
            return Decision { allowed: false, assurance, reason: Reason::ConstraintViolated { constraint: violated } };
        }
    }

    Decision { allowed: true, assurance, reason: Reason::Allowed }
}

/// Returns `Some(name)` if the constraint is violated, `None` if it holds.
fn check_constraint(
    constraint: &Constraint,
    grant: &Grant,
    capability: &CapabilityRef,
    ctx: &CapabilityContext<'_>,
) -> Option<&'static str> {
    match constraint {
        Constraint::RateLimit { max_invocations, per_seconds } => {
            let used = ctx.invocations.invocations_in(grant.principal, capability, *per_seconds, ctx.now);
            (used >= *max_invocations).then_some("rate_limit")
        }
        Constraint::TimeWindow { start, end } => {
            let now = ctx.now.time();
            let within = if start <= end {
                now >= *start && now <= *end
            } else {
                // Window wraps past midnight (e.g. 22:00–06:00).
                now >= *start || now <= *end
            };
            (!within).then_some("time_window")
        }
        Constraint::Spend { limit_minor, period } => {
            let spent = ctx.spend.spent_minor(grant.principal, capability, *period, ctx.now);
            (spent >= *limit_minor).then_some("spend")
        }
    }
}

/// Convenience: does this set, at this assurance, satisfy the requested
/// permission ignoring delegation? Used by the api layer for self-service
/// permission checks on admin endpoints.
pub fn actor_can(perms: &PermissionSet, assurance: Assurance, requested: Permission) -> bool {
    authorize(perms, None, assurance, requested).allowed
}

/// Which period a spend constraint uses, exposed so the caller can seed the
/// ledger query. Re-exported for ergonomics.
pub fn spend_period_of(constraint: &Constraint) -> Option<SpendPeriod> {
    match constraint {
        Constraint::Spend { period, .. } => Some(*period),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
