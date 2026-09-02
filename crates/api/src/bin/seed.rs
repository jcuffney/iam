//! Seed a development fixture: one org, two adult humans (one admin, one
//! ordinary user), one device, and one agent, with the five standard roles.
//!
//! Idempotent: existing orgs/roles/principals are left in place. Newly created
//! principals get fresh recovery codes and a registration token, printed once.

use iam_api::Config;
use iam_api::runtime;
use iam_auth::{generate_recovery_codes, generate_registration_token, hash_code};
use iam_core::{
    CalendarAction, CapabilityAction, ConnectionAction, MemoryAction, Org, OrgId, Permission,
    Principal, PrincipalId, PrincipalKind, Role, RoleId, Sensitivity, SpendAction, roles,
};
use iam_store::{CodePurpose, IdentityStore};
use time::OffsetDateTime;

const ORG_SLUG: &str = "cuffney";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let config = Config::from_env()?;
    let built = runtime::build(&config, None).await?;
    let store = built.state.identity();

    let org = ensure_org(store).await?;
    ensure_roles(store, org.id).await?;

    println!("Seeded org '{}' ({})", org.slug, org.id);
    println!();

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

    for (handle, display_name, kind, role_name) in fixtures {
        ensure_principal(store, &org, handle, display_name, kind, role_name).await?;
    }

    println!();
    println!("Done. Recovery codes and registration tokens above are shown ONCE.");
    Ok(())
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
) -> anyhow::Result<()> {
    if store.get_principal_by_handle(org.id, handle).await.is_ok() {
        println!("principal '{handle}' already exists — skipping");
        return Ok(());
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

    println!(
        "principal '{handle}' ({kind}) [{role_name}] id={}",
        principal.id
    );
    println!("    registration_token: {registration_token}");

    // Recovery codes for humans — devices/agents recover by admin re-issuing a
    // registration token.
    if kind == PrincipalKind::Human {
        let recovery_codes = generate_recovery_codes();
        let hashes: Vec<String> = recovery_codes
            .iter()
            .map(|c| hash_code(c))
            .collect::<Result<_, _>>()?;
        store
            .insert_codes(principal.id, CodePurpose::Recovery, &hashes)
            .await?;
        println!("    recovery_codes: {}", recovery_codes.join(", "));
    }

    Ok(())
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
