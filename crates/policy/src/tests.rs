use std::collections::BTreeSet;

use iam_core::{
    AdminAction, CalendarAction, CapabilityAction, CapabilityOperation, CapabilityRef,
    ConnectionAction, ConnectionId, Constraint, Grant, GrantId, MemoryAction, Permission,
    PermissionSet, PrincipalId, Sensitivity, SpendAction, SpendPeriod,
};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

use super::*;
use crate::ledger::{InMemoryInvocationLedger, InMemorySpendLedger, NullLedger};

fn set(perms: &[Permission]) -> PermissionSet {
    perms.iter().copied().collect()
}

/// Roughly the seeded ceilings, so the delegation tests read like reality.
fn admin_perms() -> PermissionSet {
    Permission::ALL.into_iter().collect()
}

fn device_perms() -> PermissionSet {
    set(&[
        Permission::Calendar(CalendarAction::Read),
        Permission::Memory(MemoryAction::Read, Sensitivity::Shared),
        Permission::Connection(ConnectionAction::Read),
        Permission::Capability(CapabilityAction::Invoke),
    ])
}

const NOW: OffsetDateTime = datetime!(2026-09-02 12:00:00 UTC);

// ---------------------------------------------------------------------------
// The intersection rule
// ---------------------------------------------------------------------------

#[test]
fn no_delegation_uses_the_actor_set_verbatim() {
    let actor = device_perms();
    assert_eq!(effective_permissions(&actor, None), actor);
}

#[test]
fn delegation_intersects_never_unions() {
    let device = device_perms();
    let admin = admin_perms();

    let eff = effective_permissions(&device, Some(&admin));

    // The intersection equals the device set (device ⊂ admin here)...
    assert_eq!(eff, device);
    // ...and critically is NOT the union: the admin's extra powers do not leak
    // to the device acting on the admin's behalf.
    assert!(!eff.contains(&Permission::Admin(AdminAction::ManagePrincipals)));
    assert!(!eff.contains(&Permission::Spend(SpendAction::Approve)));
    assert!(!eff.contains(&Permission::Memory(
        MemoryAction::Read,
        Sensitivity::Private
    )));
}

#[test]
fn device_acting_for_admin_cannot_exceed_the_device_ceiling() {
    let device = device_perms();
    let admin = admin_perms();

    // Something only the admin holds: denied because the device lacks it.
    let d = authorize(
        &device,
        Some(&admin),
        Assurance::Cryptographic,
        Permission::Admin(AdminAction::ManagePrincipals),
    );
    assert!(!d.allowed);
    assert_eq!(d.reason, Reason::NotPermittedForActor);

    // Even spend, which the admin holds and the device does not.
    let d = authorize(
        &device,
        Some(&admin),
        Assurance::Cryptographic,
        Permission::Spend(SpendAction::Approve),
    );
    assert!(!d.allowed);
    assert_eq!(d.reason, Reason::NotPermittedForActor);
}

#[test]
fn asserted_human_missing_permission_denies_even_when_device_has_it() {
    // Device can read shared memory; the asserted human (a guest) cannot.
    let device = device_perms();
    let guest = set(&[Permission::Calendar(CalendarAction::Read)]);

    let d = authorize(
        &device,
        Some(&guest),
        Assurance::Asserted,
        Permission::Memory(MemoryAction::Read, Sensitivity::Shared),
    );
    assert!(!d.allowed);
    assert_eq!(d.reason, Reason::NotPermittedForAsserted);
}

#[test]
fn disjoint_sets_grant_nothing() {
    let a = set(&[Permission::Calendar(CalendarAction::Read)]);
    let b = set(&[Permission::Calendar(CalendarAction::Write)]);
    assert!(effective_permissions(&a, Some(&b)).is_empty());
}

#[test]
fn delegation_is_symmetric_in_the_membership_check() {
    // Whichever side lacks the permission, the request is denied; the reason
    // distinguishes which side.
    let full = admin_perms();
    let partial = set(&[Permission::Calendar(CalendarAction::Read)]);
    let req = Permission::Calendar(CalendarAction::Write);

    // Actor lacks it.
    let d = authorize(&partial, Some(&full), Assurance::Cryptographic, req);
    assert_eq!(d.reason, Reason::NotPermittedForActor);

    // Asserted lacks it.
    let d = authorize(&full, Some(&partial), Assurance::Cryptographic, req);
    assert_eq!(d.reason, Reason::NotPermittedForAsserted);
}

// ---------------------------------------------------------------------------
// The assurance ladder — exhaustive over every permission
// ---------------------------------------------------------------------------

#[test]
fn assurance_ladder_is_enforced_for_every_permission() {
    let all = admin_perms();

    for perm in Permission::ALL {
        let required = perm.required_assurance();

        // Asserted request.
        let d = authorize(&all, None, Assurance::Asserted, perm);
        if required == Assurance::Asserted {
            assert!(d.allowed, "{perm} should be allowed at Asserted");
            assert_eq!(d.reason, Reason::Allowed);
        } else {
            assert!(!d.allowed, "{perm} must NOT be allowed at Asserted");
            assert_eq!(d.reason, Reason::InsufficientAssurance { required });
        }

        // Cryptographic request — always meets the floor when the permission
        // is held.
        let d = authorize(&all, None, Assurance::Cryptographic, perm);
        assert!(d.allowed, "{perm} should be allowed at Cryptographic");
        assert_eq!(d.reason, Reason::Allowed);
    }
}

#[test]
fn private_memory_is_refused_at_asserted() {
    let all = admin_perms();
    for action in [MemoryAction::Read, MemoryAction::Write] {
        let d = authorize(
            &all,
            None,
            Assurance::Asserted,
            Permission::Memory(action, Sensitivity::Private),
        );
        assert!(!d.allowed);
        assert_eq!(
            d.reason,
            Reason::InsufficientAssurance {
                required: Assurance::Cryptographic
            }
        );
    }
}

#[test]
fn shared_memory_and_calendar_are_fine_at_asserted() {
    let all = admin_perms();
    for perm in [
        Permission::Memory(MemoryAction::Read, Sensitivity::Shared),
        Permission::Memory(MemoryAction::Write, Sensitivity::Shared),
        Permission::Calendar(CalendarAction::Read),
        Permission::Calendar(CalendarAction::Write),
    ] {
        assert!(
            authorize(&all, None, Assurance::Asserted, perm).allowed,
            "{perm}"
        );
    }
}

#[test]
fn connection_manage_requires_cryptographic_but_read_does_not() {
    let all = admin_perms();
    // A voice-asserted identity may use a connection...
    assert!(
        authorize(
            &all,
            None,
            Assurance::Asserted,
            Permission::Connection(ConnectionAction::Read)
        )
        .allowed
    );
    // ...but may never manage (grant/revoke) one.
    let d = authorize(
        &all,
        None,
        Assurance::Asserted,
        Permission::Connection(ConnectionAction::Manage),
    );
    assert!(!d.allowed);
    assert_eq!(
        d.reason,
        Reason::InsufficientAssurance {
            required: Assurance::Cryptographic
        }
    );
}

#[test]
fn assurance_and_intersection_compose() {
    // Device asserting admin for private memory: the device lacks the
    // permission, so it fails on membership before assurance is even reached.
    let device = device_perms();
    let admin = admin_perms();
    let d = authorize(
        &device,
        Some(&admin),
        Assurance::Cryptographic,
        Permission::Memory(MemoryAction::Read, Sensitivity::Private),
    );
    assert!(!d.allowed);
    assert_eq!(d.reason, Reason::NotPermittedForActor);
}

// ---------------------------------------------------------------------------
// Capability invocation
// ---------------------------------------------------------------------------

fn cap_ref() -> CapabilityRef {
    CapabilityRef {
        connection_id: ConnectionId::new(),
        operation: CapabilityOperation::ModelEndpoint {
            name: "claude-fable-5".into(),
        },
    }
}

fn live_grant(principal: PrincipalId, constraints: Vec<Constraint>) -> Grant {
    Grant {
        id: GrantId::new(),
        principal,
        capability: cap_ref(),
        constraints,
        expires_at: None,
        granted_by: PrincipalId::new(),
        created_at: NOW - Duration::days(1),
        revoked_at: None,
    }
}

fn invoker_perms() -> PermissionSet {
    set(&[Permission::Capability(CapabilityAction::Invoke)])
}

#[test]
fn invocation_needs_a_grant() {
    let perms = invoker_perms();
    let d = authorize_capability_invocation(
        &perms,
        None,
        Assurance::Asserted,
        &cap_ref(),
        CapabilityContext {
            grant: None,
            connection_active: true,
            now: NOW,
            spend: &NullLedger,
            invocations: &NullLedger,
        },
    );
    assert!(!d.allowed);
    assert_eq!(d.reason, Reason::NoGrant);
}

#[test]
fn invocation_needs_the_base_permission_first() {
    // No capability:invoke permission → denied before grant logic.
    let perms = set(&[Permission::Calendar(CalendarAction::Read)]);
    let principal = PrincipalId::new();
    let grant = live_grant(principal, vec![]);
    let d = authorize_capability_invocation(
        &perms,
        None,
        Assurance::Asserted,
        &cap_ref(),
        CapabilityContext {
            grant: Some(&grant),
            connection_active: true,
            now: NOW,
            spend: &NullLedger,
            invocations: &NullLedger,
        },
    );
    assert!(!d.allowed);
    assert_eq!(d.reason, Reason::NotPermittedForActor);
}

#[test]
fn delegated_device_may_invoke_a_granted_capability() {
    // Device (asserted human) both hold capability:invoke; grant is for the
    // effective principal (the human).
    let device = device_perms();
    let human = set(&[Permission::Capability(CapabilityAction::Invoke)]);
    let human_id = PrincipalId::new();
    let grant = live_grant(human_id, vec![]);

    let d = authorize_capability_invocation(
        &device,
        Some(&human),
        Assurance::Asserted,
        &cap_ref(),
        CapabilityContext {
            grant: Some(&grant),
            connection_active: true,
            now: NOW,
            spend: &NullLedger,
            invocations: &NullLedger,
        },
    );
    assert!(d.allowed, "{:?}", d.reason);
}

#[test]
fn expired_grant_is_refused_even_when_role_permits() {
    let perms = invoker_perms();
    let principal = PrincipalId::new();
    let mut grant = live_grant(principal, vec![]);
    grant.expires_at = Some(NOW - Duration::hours(1));

    let d = authorize_capability_invocation(
        &perms,
        None,
        Assurance::Cryptographic,
        &cap_ref(),
        CapabilityContext {
            grant: Some(&grant),
            connection_active: true,
            now: NOW,
            spend: &NullLedger,
            invocations: &NullLedger,
        },
    );
    assert!(!d.allowed);
    assert_eq!(d.reason, Reason::GrantExpired);
}

#[test]
fn revoked_grant_is_refused() {
    let perms = invoker_perms();
    let principal = PrincipalId::new();
    let mut grant = live_grant(principal, vec![]);
    grant.revoked_at = Some(NOW - Duration::minutes(5));

    let d = authorize_capability_invocation(
        &perms,
        None,
        Assurance::Cryptographic,
        &cap_ref(),
        CapabilityContext {
            grant: Some(&grant),
            connection_active: true,
            now: NOW,
            spend: &NullLedger,
            invocations: &NullLedger,
        },
    );
    assert!(!d.allowed);
    assert_eq!(d.reason, Reason::GrantRevoked);
}

#[test]
fn inactive_connection_refuses_the_grant() {
    let perms = invoker_perms();
    let principal = PrincipalId::new();
    let grant = live_grant(principal, vec![]);

    let d = authorize_capability_invocation(
        &perms,
        None,
        Assurance::Cryptographic,
        &cap_ref(),
        // connection_active=false models a revoked connection: every dependent
        // grant is dead immediately.
        CapabilityContext {
            grant: Some(&grant),
            connection_active: false,
            now: NOW,
            spend: &NullLedger,
            invocations: &NullLedger,
        },
    );
    assert!(!d.allowed);
    assert_eq!(d.reason, Reason::ConnectionInactive);
}

#[test]
fn spend_constraint_is_checked_against_the_ledger_before_allowing() {
    let perms = invoker_perms();
    let principal = PrincipalId::new();
    let cap = cap_ref();
    let grant = live_grant(
        principal,
        vec![Constraint::Spend {
            limit_minor: 1000,
            period: SpendPeriod::Day,
        }],
    );

    let spend = InMemorySpendLedger::new();

    // Under the limit → allowed.
    spend.record(principal, &cap, 400, NOW - Duration::hours(2));
    let d = authorize_capability_invocation(
        &perms,
        None,
        Assurance::Cryptographic,
        &cap,
        CapabilityContext {
            grant: Some(&grant),
            connection_active: true,
            now: NOW,
            spend: &spend,
            invocations: &NullLedger,
        },
    );
    assert!(d.allowed, "{:?}", d.reason);

    // Push spend to the limit → refused before invocation.
    spend.record(principal, &cap, 600, NOW - Duration::hours(1));
    let d = authorize_capability_invocation(
        &perms,
        None,
        Assurance::Cryptographic,
        &cap,
        CapabilityContext {
            grant: Some(&grant),
            connection_active: true,
            now: NOW,
            spend: &spend,
            invocations: &NullLedger,
        },
    );
    assert!(!d.allowed);
    assert_eq!(
        d.reason,
        Reason::ConstraintViolated {
            constraint: "spend"
        }
    );
}

#[test]
fn rate_limit_constraint_is_enforced() {
    let perms = invoker_perms();
    let principal = PrincipalId::new();
    let cap = cap_ref();
    let grant = live_grant(
        principal,
        vec![Constraint::RateLimit {
            max_invocations: 2,
            per_seconds: 60,
        }],
    );
    let invocations = InMemoryInvocationLedger::new();

    invocations.record(principal, &cap, NOW - Duration::seconds(10));
    let d = authorize_capability_invocation(
        &perms,
        None,
        Assurance::Asserted,
        &cap,
        CapabilityContext {
            grant: Some(&grant),
            connection_active: true,
            now: NOW,
            spend: &NullLedger,
            invocations: &invocations,
        },
    );
    assert!(d.allowed);

    invocations.record(principal, &cap, NOW - Duration::seconds(5));
    let d = authorize_capability_invocation(
        &perms,
        None,
        Assurance::Asserted,
        &cap,
        CapabilityContext {
            grant: Some(&grant),
            connection_active: true,
            now: NOW,
            spend: &NullLedger,
            invocations: &invocations,
        },
    );
    assert!(!d.allowed);
    assert_eq!(
        d.reason,
        Reason::ConstraintViolated {
            constraint: "rate_limit"
        }
    );
}

#[test]
fn time_window_constraint_allows_inside_and_denies_outside() {
    let perms = invoker_perms();
    let principal = PrincipalId::new();
    let cap = cap_ref();

    // Allowed window 08:00–18:00; NOW is 12:00.
    let grant = live_grant(
        principal,
        vec![Constraint::TimeWindow {
            start: time::macros::time!(08:00),
            end: time::macros::time!(18:00),
        }],
    );
    let d = authorize_capability_invocation(
        &perms,
        None,
        Assurance::Asserted,
        &cap,
        CapabilityContext {
            grant: Some(&grant),
            connection_active: true,
            now: NOW,
            spend: &NullLedger,
            invocations: &NullLedger,
        },
    );
    assert!(d.allowed);

    // Window 20:00–23:00 excludes NOW.
    let grant = live_grant(
        principal,
        vec![Constraint::TimeWindow {
            start: time::macros::time!(20:00),
            end: time::macros::time!(23:00),
        }],
    );
    let d = authorize_capability_invocation(
        &perms,
        None,
        Assurance::Asserted,
        &cap,
        CapabilityContext {
            grant: Some(&grant),
            connection_active: true,
            now: NOW,
            spend: &NullLedger,
            invocations: &NullLedger,
        },
    );
    assert!(!d.allowed);
    assert_eq!(
        d.reason,
        Reason::ConstraintViolated {
            constraint: "time_window"
        }
    );
}

#[test]
fn overnight_time_window_wraps_midnight() {
    let perms = invoker_perms();
    let principal = PrincipalId::new();
    let cap = cap_ref();
    // 22:00–06:00 window. 02:00 is inside; 12:00 is outside.
    let grant = live_grant(
        principal,
        vec![Constraint::TimeWindow {
            start: time::macros::time!(22:00),
            end: time::macros::time!(06:00),
        }],
    );

    let at_night = datetime!(2026-09-02 02:00:00 UTC);
    let d = authorize_capability_invocation(
        &perms,
        None,
        Assurance::Asserted,
        &cap,
        CapabilityContext {
            grant: Some(&grant),
            connection_active: true,
            now: at_night,
            spend: &NullLedger,
            invocations: &NullLedger,
        },
    );
    assert!(d.allowed);

    let d = authorize_capability_invocation(
        &perms,
        None,
        Assurance::Asserted,
        &cap,
        CapabilityContext {
            grant: Some(&grant),
            connection_active: true,
            now: NOW,
            spend: &NullLedger,
            invocations: &NullLedger,
        },
    );
    assert!(!d.allowed);
}

#[test]
fn ledger_respects_period_boundaries() {
    let principal = PrincipalId::new();
    let cap = cap_ref();
    let spend = InMemorySpendLedger::new();
    // A spend from last month should not count against this month's daily or
    // monthly window.
    spend.record(principal, &cap, 5000, datetime!(2026-08-15 12:00:00 UTC));
    assert_eq!(
        spend.spent_minor(principal, &cap, SpendPeriod::Month, NOW),
        0
    );
    assert_eq!(spend.spent_minor(principal, &cap, SpendPeriod::Day, NOW), 0);

    // A spend earlier today counts for the day and the month.
    spend.record(principal, &cap, 700, NOW - Duration::hours(3));
    assert_eq!(
        spend.spent_minor(principal, &cap, SpendPeriod::Day, NOW),
        700
    );
    assert_eq!(
        spend.spent_minor(principal, &cap, SpendPeriod::Month, NOW),
        700
    );
}

#[test]
fn multiple_constraints_all_must_hold() {
    let perms = invoker_perms();
    let principal = PrincipalId::new();
    let cap = cap_ref();
    let spend = InMemorySpendLedger::new();
    let grant = live_grant(
        principal,
        vec![
            Constraint::Spend {
                limit_minor: 1000,
                period: SpendPeriod::Day,
            },
            Constraint::TimeWindow {
                start: time::macros::time!(08:00),
                end: time::macros::time!(18:00),
            },
        ],
    );
    // Spend fine, time fine → allowed.
    let d = authorize_capability_invocation(
        &perms,
        None,
        Assurance::Asserted,
        &cap,
        CapabilityContext {
            grant: Some(&grant),
            connection_active: true,
            now: NOW,
            spend: &spend,
            invocations: &NullLedger,
        },
    );
    assert!(d.allowed);

    // Blow the spend cap → denied even though time still holds.
    spend.record(principal, &cap, 1000, NOW - Duration::hours(1));
    let d = authorize_capability_invocation(
        &perms,
        None,
        Assurance::Asserted,
        &cap,
        CapabilityContext {
            grant: Some(&grant),
            connection_active: true,
            now: NOW,
            spend: &spend,
            invocations: &NullLedger,
        },
    );
    assert!(!d.allowed);
    assert_eq!(
        d.reason,
        Reason::ConstraintViolated {
            constraint: "spend"
        }
    );
}

#[test]
fn effective_permissions_is_never_larger_than_either_input() {
    // Property: for any two sets, the intersection size is bounded by both.
    let a = admin_perms();
    let b = device_perms();
    let eff = effective_permissions(&a, Some(&b));
    assert!(eff.len() <= a.len());
    assert!(eff.len() <= b.len());
    assert!(eff.is_subset(&a));
    assert!(eff.is_subset(&b));
    // And it equals set intersection computed independently.
    let manual: BTreeSet<Permission> = a.intersection(&b).copied().collect();
    assert_eq!(eff, manual);
}
