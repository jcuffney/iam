//! Integration tests against live Postgres and DynamoDB Local.
//!
//! Marked `#[ignore]` so `cargo test` stays container-free; run them with the
//! docker-compose services up:
//!
//! ```bash
//! docker compose up -d
//! cargo test -p iam-store -- --ignored
//! ```
//!
//! They read `DATABASE_URL` and `DYNAMO_ENDPOINT` (falling back to the
//! docker-compose defaults) and use unique identifiers so repeated runs and the
//! seeded fixture never collide.

use std::net::{IpAddr, Ipv4Addr};

use iam_core::{
    Assurance, AuditDecision, AuditEvent, CalendarAction, Credential, MemoryAction, Org, OrgId,
    PasskeyCredential, Permission, Principal, PrincipalId, PrincipalKind, Role, RoleId,
    Sensitivity,
};
use iam_store::{
    AuditFilter, AuditStore, ChallengeMode, ChallengeRecord, DynamoStore, IdentityStore, PgStore,
    SessionRecord, SessionScope, connect_dynamo, connect_postgres, run_identity_migrations,
};
use time::{Duration, OffsetDateTime};

fn database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://iam:iam@localhost:5432/iam".into())
}

fn dynamo_endpoint() -> String {
    std::env::var("DYNAMO_ENDPOINT").unwrap_or_else(|_| "http://localhost:8001".into())
}

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

async fn pg() -> PgStore {
    // Ensure AWS-style credentials exist for the Dynamo client used elsewhere;
    // harmless here.
    let pool = connect_postgres(&database_url(), 5)
        .await
        .expect("connect postgres");
    run_identity_migrations(&pool).await.expect("migrate");
    PgStore::new(pool)
}

async fn seed_org(store: &PgStore) -> Org {
    let org = Org {
        id: OrgId::new(),
        slug: unique("org"),
        name: "Live Test".into(),
        created_at: OffsetDateTime::now_utc(),
    };
    store.create_org(&org).await.unwrap();
    org
}

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn postgres_identity_round_trip() {
    let store = pg().await;
    let org = seed_org(&store).await;

    // Principal.
    let principal = Principal {
        id: PrincipalId::new(),
        org_id: org.id,
        kind: PrincipalKind::Human,
        handle: unique("handle"),
        display_name: "Live Human".into(),
        created_at: OffsetDateTime::now_utc(),
        disabled_at: None,
    };
    store.create_principal(&principal).await.unwrap();
    assert_eq!(
        store.get_principal(principal.id).await.unwrap().handle,
        principal.handle
    );

    // Role + permissions + assignment, then the union query.
    let role = Role {
        id: RoleId::new(),
        org_id: org.id,
        name: unique("role"),
    };
    store.create_role(&role).await.unwrap();
    let perms = vec![
        Permission::Calendar(CalendarAction::Read),
        Permission::Memory(MemoryAction::Read, Sensitivity::Private),
    ];
    store.set_role_permissions(role.id, &perms).await.unwrap();
    store.assign_role(principal.id, role.id).await.unwrap();

    let resolved = store.permissions_for_principal(principal.id).await.unwrap();
    assert!(resolved.contains(&Permission::Calendar(CalendarAction::Read)));
    assert!(resolved.contains(&Permission::Memory(
        MemoryAction::Read,
        Sensitivity::Private
    )));

    // Disable / enable.
    store
        .set_principal_disabled(principal.id, Some(OffsetDateTime::now_utc()))
        .await
        .unwrap();
    assert!(
        store
            .get_principal(principal.id)
            .await
            .unwrap()
            .is_disabled()
    );
    store
        .set_principal_disabled(principal.id, None)
        .await
        .unwrap();
    assert!(
        !store
            .get_principal(principal.id)
            .await
            .unwrap()
            .is_disabled()
    );
}

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn postgres_credential_insert_is_idempotent() {
    let store = pg().await;
    let org = seed_org(&store).await;
    let principal = Principal {
        id: PrincipalId::new(),
        org_id: org.id,
        kind: PrincipalKind::Device,
        handle: unique("dev"),
        display_name: "Live Device".into(),
        created_at: OffsetDateTime::now_utc(),
        disabled_at: None,
    };
    store.create_principal(&principal).await.unwrap();

    let cred = Credential::Passkey(PasskeyCredential {
        credential_id: unique("cred").into_bytes(),
        principal_id: principal.id,
        passkey_blob: b"{}".to_vec(),
        sign_count: 0,
        transports: vec!["internal".into()],
        aaguid: None,
        nickname: Some("phone".into()),
        created_at: OffsetDateTime::now_utc(),
        last_used_at: None,
    });

    assert!(
        store.insert_credential(&cred).await.unwrap(),
        "first insert is new"
    );
    assert!(
        !store.insert_credential(&cred).await.unwrap(),
        "retry is idempotent"
    );
    assert_eq!(store.list_credentials(principal.id).await.unwrap().len(), 1);
}

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn postgres_audit_append_and_query() {
    let store = pg().await;
    let org = seed_org(&store).await;
    let actor = Principal {
        id: PrincipalId::new(),
        org_id: org.id,
        kind: PrincipalKind::Human,
        handle: unique("actor"),
        display_name: "Actor".into(),
        created_at: OffsetDateTime::now_utc(),
        disabled_at: None,
    };
    store.create_principal(&actor).await.unwrap();

    let event = AuditEvent {
        org_id: org.id,
        actor_id: actor.id,
        asserted_id: None,
        action: "memory:read:private".into(),
        decision: AuditDecision::Allow,
        assurance: Some(Assurance::Cryptographic),
        reason: Some("live test".into()),
        ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        occurred_at: OffsetDateTime::now_utc(),
    };
    store.append(&event).await.unwrap();

    let results = store
        .query(&AuditFilter {
            org_id: Some(org.id),
            limit: 10,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].action, "memory:read:private");
    assert_eq!(results[0].assurance, Some(Assurance::Cryptographic));
    assert_eq!(results[0].ip, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
}

#[tokio::test]
#[ignore = "requires live DynamoDB Local"]
async fn dynamo_challenge_is_consumed_once() {
    unsafe {
        std::env::set_var("AWS_ACCESS_KEY_ID", "local");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "local");
        std::env::set_var("AWS_REGION", "us-east-1");
    }
    let client = connect_dynamo(Some(&dynamo_endpoint())).await;
    let store = DynamoStore::new(client);
    store.ensure_tables().await.unwrap();

    use iam_store::ChallengeStore;
    let now = OffsetDateTime::now_utc();
    let record = ChallengeRecord {
        challenge_id: unique("chal"),
        mode: ChallengeMode::Auth,
        principal_id: PrincipalId::new(),
        org_id: OrgId::new(),
        state_blob: b"state".to_vec(),
        expires_at: now + Duration::minutes(5),
    };
    store.put_challenge(&record).await.unwrap();

    // First take succeeds; the second returns None (consume-once).
    let taken = store
        .take_challenge(&record.challenge_id, now)
        .await
        .unwrap();
    assert!(taken.is_some());
    assert_eq!(taken.unwrap().state_blob, b"state");
    assert!(
        store
            .take_challenge(&record.challenge_id, now)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
#[ignore = "requires live DynamoDB Local"]
async fn dynamo_expired_records_are_rejected_in_code() {
    unsafe {
        std::env::set_var("AWS_ACCESS_KEY_ID", "local");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "local");
        std::env::set_var("AWS_REGION", "us-east-1");
    }
    let client = connect_dynamo(Some(&dynamo_endpoint())).await;
    let store = DynamoStore::new(client);
    store.ensure_tables().await.unwrap();

    use iam_store::{ChallengeStore, SessionStore};
    let now = OffsetDateTime::now_utc();

    // A past-dated session must be rejected even though DynamoDB Local never
    // sweeps TTL.
    let session = SessionRecord {
        session_id: unique("sess"),
        principal_id: PrincipalId::new(),
        org_id: OrgId::new(),
        assurance: Assurance::Cryptographic,
        scope: SessionScope::Full,
        created_at: now - Duration::hours(2),
        expires_at: now - Duration::hours(1),
    };
    store.put_session(&session).await.unwrap();
    assert!(
        store
            .get_session(&session.session_id, now)
            .await
            .unwrap()
            .is_none(),
        "expired session rejected"
    );

    // Same for challenges.
    let challenge = ChallengeRecord {
        challenge_id: unique("chal"),
        mode: ChallengeMode::RegisterFirst,
        principal_id: PrincipalId::new(),
        org_id: OrgId::new(),
        state_blob: b"x".to_vec(),
        expires_at: now - Duration::minutes(1),
    };
    store.put_challenge(&challenge).await.unwrap();
    assert!(
        store
            .take_challenge(&challenge.challenge_id, now)
            .await
            .unwrap()
            .is_none(),
        "expired challenge rejected"
    );

    // A live session round-trips and revokes.
    let live = SessionRecord {
        session_id: unique("sess"),
        principal_id: PrincipalId::new(),
        org_id: OrgId::new(),
        assurance: Assurance::Asserted,
        scope: SessionScope::CredentialRegistrationOnly,
        created_at: now,
        expires_at: now + Duration::hours(1),
    };
    store.put_session(&live).await.unwrap();
    assert!(
        store
            .get_session(&live.session_id, now)
            .await
            .unwrap()
            .is_some()
    );
    store.revoke_session(&live.session_id).await.unwrap();
    assert!(
        store
            .get_session(&live.session_id, now)
            .await
            .unwrap()
            .is_none()
    );
}
