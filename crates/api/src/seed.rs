//! The idempotent seed fixture: one org, the five standard roles, and four
//! fixture principals.
//!
//! Shared by the `seed` CLI (which prints the report) and the `admin` binary
//! (which returns it in a Lambda invoke response payload, keeping registration
//! tokens and recovery codes out of logs). Existing orgs/roles/principals are
//! left in place; newly created principals get fresh codes, reported once.

use iam_auth::{generate_recovery_codes, generate_registration_token, hash_code};
use iam_core::{
    CalendarAction, CapabilityAction, ConnectionAction, MemoryAction, Org, OrgId, Permission,
    Principal, PrincipalId, PrincipalKind, Role, RoleId, Sensitivity, SpendAction, roles,
};
use iam_store::{CodePurpose, IdentityStore};
use serde::Serialize;
use time::OffsetDateTime;

const ORG_SLUG: &str = "cuffney";

/// Everything one seed run did. Registration tokens and recovery codes appear
/// only for principals created by this run, and are shown exactly once.
#[derive(Serialize)]
pub struct SeedReport {
    pub org_slug: String,
    pub org_id: String,
    pub principals: Vec<PrincipalReport>,
}

#[derive(Serialize)]
pub struct PrincipalReport {
    pub handle: String,
    pub kind: String,
    pub role: String,
    pub id: String,
    /// `false` when the principal already existed and was left untouched.
    pub created: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_codes: Option<Vec<String>>,
}

/// Run the fixture against the identity store. Safe to repeat.
pub async fn run(store: &dyn IdentityStore) -> anyhow::Result<SeedReport> {
    let org = ensure_org(store).await?;
    ensure_roles(store, org.id).await?;

    // Fixture principals: (handle, display name, kind, role).
    let fixtures = [
        ("joe", "Joe Cuffney", PrincipalKind::Human, roles::ADMIN),
        ("jane", "Jane Cuffney", PrincipalKind::Human, roles::USER),
        (
            "gym-speaker",
            "Basement Gym Speaker",
            PrincipalKind::Device,
            roles::DEVICE,
        ),
        ("jarvis", "Jarvis Agent", PrincipalKind::Agent, roles::AGENT),
    ];

    let mut principals = Vec::with_capacity(fixtures.len());
    for (handle, display_name, kind, role_name) in fixtures {
        principals
            .push(ensure_principal(store, &org, handle, display_name, kind, role_name).await?);
    }

    Ok(SeedReport {
        org_slug: org.slug,
        org_id: org.id.to_string(),
        principals,
    })
}

async fn ensure_org(store: &dyn IdentityStore) -> anyhow::Result<Org> {
    if let Ok(existing) = store.get_org_by_slug(ORG_SLUG).await {
        return Ok(existing);
    }
    let org = Org {
        id: OrgId::new(),
        slug: ORG_SLUG.to_string(),
        name: "Cuffney Household".to_string(),
        created_at: OffsetDateTime::now_utc(),
    };
    store.create_org(&org).await?;
    Ok(org)
}

async fn ensure_roles(store: &dyn IdentityStore, org_id: OrgId) -> anyhow::Result<()> {
    for name in roles::ALL {
        let role = match store.get_role_by_name(org_id, name).await {
            Ok(r) => r,
            Err(_) => {
                let r = Role {
                    id: RoleId::new(),
                    org_id,
                    name: name.to_string(),
                };
                store.create_role(&r).await?;
                r
            }
        };
        // Always (re)assert the permission set so the fixture stays canonical.
        store
            .set_role_permissions(role.id, &permissions_for(name))
            .await?;
    }
    Ok(())
}

async fn ensure_principal(
    store: &dyn IdentityStore,
    org: &Org,
    handle: &str,
    display_name: &str,
    kind: PrincipalKind,
    role_name: &str,
) -> anyhow::Result<PrincipalReport> {
    if let Ok(existing) = store.get_principal_by_handle(org.id, handle).await {
        return Ok(PrincipalReport {
            handle: handle.to_string(),
            kind: kind.to_string(),
            role: role_name.to_string(),
            id: existing.id.to_string(),
            created: false,
            registration_token: None,
            recovery_codes: None,
        });
    }

    let principal = Principal {
        id: PrincipalId::new(),
        org_id: org.id,
        kind,
        handle: handle.to_string(),
        display_name: display_name.to_string(),
        created_at: OffsetDateTime::now_utc(),
        disabled_at: None,
    };
    store.create_principal(&principal).await?;

    let role = store.get_role_by_name(org.id, role_name).await?;
    store.assign_role(principal.id, role.id).await?;

    // Registration token so the first credential can be bound.
    let registration_token = generate_registration_token();
    store
        .insert_codes(
            principal.id,
            CodePurpose::Registration,
            &[hash_code(&registration_token)?],
        )
        .await?;

    // Recovery codes for humans — devices/agents recover by admin re-issuing a
    // registration token.
    let recovery_codes = if kind == PrincipalKind::Human {
        let codes = generate_recovery_codes();
        let hashes: Vec<String> = codes
            .iter()
            .map(|c| hash_code(c))
            .collect::<Result<_, _>>()?;
        store
            .insert_codes(principal.id, CodePurpose::Recovery, &hashes)
            .await?;
        Some(codes)
    } else {
        None
    };

    Ok(PrincipalReport {
        handle: handle.to_string(),
        kind: kind.to_string(),
        role: role_name.to_string(),
        id: principal.id.to_string(),
        created: true,
        registration_token: Some(registration_token),
        recovery_codes,
    })
}

/// The canonical permission set for each seeded role.
fn permissions_for(role: &str) -> Vec<Permission> {
    use Permission::*;
    match role {
        roles::ADMIN => Permission::ALL.to_vec(),
        roles::USER => vec![
            Calendar(CalendarAction::Read),
            Calendar(CalendarAction::Write),
            Memory(MemoryAction::Read, Sensitivity::Shared),
            Memory(MemoryAction::Read, Sensitivity::Private),
            Memory(MemoryAction::Write, Sensitivity::Shared),
            Memory(MemoryAction::Write, Sensitivity::Private),
            Spend(SpendAction::Approve),
            Connection(ConnectionAction::Read),
            Connection(ConnectionAction::Manage),
            Capability(CapabilityAction::Invoke),
        ],
        roles::GUEST => vec![
            Calendar(CalendarAction::Read),
            Memory(MemoryAction::Read, Sensitivity::Shared),
        ],
        roles::DEVICE => vec![
            Calendar(CalendarAction::Read),
            Memory(MemoryAction::Read, Sensitivity::Shared),
            Connection(ConnectionAction::Read),
            Capability(CapabilityAction::Invoke),
        ],
        roles::AGENT => vec![
            Calendar(CalendarAction::Read),
            Calendar(CalendarAction::Write),
            Memory(MemoryAction::Read, Sensitivity::Shared),
            Memory(MemoryAction::Write, Sensitivity::Shared),
            Connection(ConnectionAction::Read),
            Capability(CapabilityAction::Invoke),
        ],
        _ => vec![],
    }
}
