//! End-to-end integration tests.
//!
//! Everything runs in-process: the real `axum` router over in-memory stores,
//! driven through `tower::ServiceExt::oneshot`, with a virtual authenticator
//! (`SoftPasskey`) performing full WebAuthn ceremonies. No containers, no
//! sockets. These cover the ceremonies, the delegation rule, the assurance
//! ladder, clone detection, idempotency, session lifecycle, and the
//! capability/grant model.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use http_body_util::BodyExt;
use iam_api::build_router;
use iam_api::state::{AppState, AppStateParts, RateLimiters};
use iam_auth::ceremony::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};
use iam_auth::{EnvKeySource, KeyRing, WebauthnService, generate_registration_token, hash_code};
use iam_connections::{EncryptionKey, MemoryConnectionsStore};
use iam_core::{
    Org, OrgId, Permission, Principal, PrincipalId, PrincipalKind, Role, RoleId, roles,
};
use iam_policy::{InMemoryInvocationLedger, InMemorySpendLedger};
use iam_store::{
    AuditStore, CodePurpose, IdentityStore, MemoryAuditStore, MemoryChallengeStore,
    MemoryIdentityStore, MemorySessionStore,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt;
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;

const ORG_SLUG: &str = "testorg";
const ORIGIN: &str = "http://localhost:8080";

/// The test rig: the router plus direct handles to the in-memory stores and
/// ledgers for seeding and assertions.
struct Env {
    router: Router,
    identity: Arc<MemoryIdentityStore>,
    audit: Arc<MemoryAuditStore>,
    org: Org,
}

impl Env {
    async fn new() -> Self {
        let identity = Arc::new(MemoryIdentityStore::new());
        let audit = Arc::new(MemoryAuditStore::new());
        let challenges = Arc::new(MemoryChallengeStore::new());
        let sessions = Arc::new(MemorySessionStore::new());
        let connections = Arc::new(MemoryConnectionsStore::new(
            EncryptionKey::from_bytes(&[42u8; 32]).unwrap(),
        ));
        let spend = Arc::new(InMemorySpendLedger::new());
        let invocations = Arc::new(InMemoryInvocationLedger::new());

        let webauthn = Arc::new(WebauthnService::new("localhost", ORIGIN, "iam-test").unwrap());
        let keyring = Arc::new(test_keyring());

        let state = AppState::new(AppStateParts {
            identity: identity.clone(),
            audit: audit.clone(),
            challenges,
            sessions,
            connections,
            webauthn,
            keyring,
            spend: spend.clone(),
            invocations,
            token_ttl: Duration::from_secs(900),
            session_ttl: Duration::from_secs(43_200),
            trusted_proxy_hops: 0,
            limiters: Arc::new(RateLimiters::new(10_000)),
            metrics: None,
            metrics_token: None,
        });

        let router = build_router(state);

        // Seed the org and the standard roles directly.
        let org = Org {
            id: OrgId::new(),
            slug: ORG_SLUG.into(),
            name: "Test Org".into(),
            created_at: OffsetDateTime::now_utc(),
        };
        identity.create_org(&org).await.unwrap();
        for name in roles::ALL {
            let role = Role {
                id: RoleId::new(),
                org_id: org.id,
                name: name.into(),
            };
            identity.create_role(&role).await.unwrap();
            identity
                .set_role_permissions(role.id, &seed_permissions(name))
                .await
                .unwrap();
        }

        Env {
            router,
            identity,
            audit,
            org,
        }
    }

    /// Create a principal directly and assign a role. Returns its id.
    async fn seed_principal(&self, handle: &str, kind: PrincipalKind, role: &str) -> PrincipalId {
        let principal = Principal {
            id: PrincipalId::new(),
            org_id: self.org.id,
            kind,
            handle: handle.into(),
            display_name: handle.into(),
            created_at: OffsetDateTime::now_utc(),
            disabled_at: None,
        };
        self.identity.create_principal(&principal).await.unwrap();
        let r = self
            .identity
            .get_role_by_name(self.org.id, role)
            .await
            .unwrap();
        self.identity.assign_role(principal.id, r.id).await.unwrap();
        principal.id
    }

    /// Issue a registration token for a principal (hash stored, plaintext
    /// returned) — mirrors what `POST /principals` does.
    async fn issue_registration_token(&self, pid: PrincipalId) -> String {
        let token = generate_registration_token();
        self.identity
            .insert_codes(
                pid,
                CodePurpose::Registration,
                &[hash_code(&token).unwrap()],
            )
            .await
            .unwrap();
        token
    }

    /// A raw HTTP call returning status + parsed JSON body.
    async fn call(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let request = if let Some(json) = body {
            builder
                .header("content-type", "application/json")
                .body(Body::from(json.to_string()))
                .unwrap()
        } else {
            builder.body(Body::empty()).unwrap()
        };

        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value: Value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, value)
    }
}

/// A simulated physical authenticator (one device).
struct Device {
    authr: WebauthnAuthenticator<SoftPasskey>,
}

impl Device {
    fn new() -> Self {
        // falsify_uv = true: webauthn-rs passkey auth requires user verification.
        Self {
            authr: WebauthnAuthenticator::new(SoftPasskey::new(true)),
        }
    }

    /// Drive a full first-credential registration ceremony.
    async fn register(&mut self, env: &Env, handle: &str, token: &str) -> (StatusCode, Value) {
        let (status, body) = env
            .call(
                "POST",
                "/register/start",
                None,
                Some(json!({"org_slug": ORG_SLUG, "handle": handle, "registration_token": token})),
            )
            .await;
        if status != StatusCode::OK {
            return (status, body);
        }
        let challenge_id = body["challenge_id"].as_str().unwrap().to_string();
        let ccr: CreationChallengeResponse =
            serde_json::from_value(body["publicKey"].clone()).unwrap();
        let credential = self
            .authr
            .do_registration(Url::parse(ORIGIN).unwrap(), ccr)
            .unwrap();
        env.call(
            "POST",
            "/register/finish",
            None,
            Some(json!({"challenge_id": challenge_id, "credential": serde_json::to_value(&credential).unwrap(), "nickname": handle})),
        )
        .await
    }

    /// Build (but do not submit) a registration credential for idempotency
    /// testing — returns the finish body so it can be submitted twice.
    async fn registration_finish_body(&mut self, env: &Env, handle: &str, token: &str) -> Value {
        let (_s, body) = env
            .call(
                "POST",
                "/register/start",
                None,
                Some(json!({"org_slug": ORG_SLUG, "handle": handle, "registration_token": token})),
            )
            .await;
        let challenge_id = body["challenge_id"].as_str().unwrap().to_string();
        let ccr: CreationChallengeResponse =
            serde_json::from_value(body["publicKey"].clone()).unwrap();
        let credential: RegisterPublicKeyCredential = self
            .authr
            .do_registration(Url::parse(ORIGIN).unwrap(), ccr)
            .unwrap();
        json!({"challenge_id": challenge_id, "credential": serde_json::to_value(&credential).unwrap()})
    }

    /// Add this device to an already-authenticated principal (device-add flow).
    async fn add_to_session(&mut self, env: &Env, session_token: &str) -> (StatusCode, Value) {
        let (status, body) = env
            .call("POST", "/register/device/start", Some(session_token), None)
            .await;
        if status != StatusCode::OK {
            return (status, body);
        }
        let challenge_id = body["challenge_id"].as_str().unwrap().to_string();
        let ccr: CreationChallengeResponse =
            serde_json::from_value(body["publicKey"].clone()).unwrap();
        let credential = self
            .authr
            .do_registration(Url::parse(ORIGIN).unwrap(), ccr)
            .unwrap();
        env.call(
            "POST",
            "/register/finish",
            None,
            Some(json!({"challenge_id": challenge_id, "credential": serde_json::to_value(&credential).unwrap()})),
        )
        .await
    }

    /// Drive a full authentication ceremony, returning the token response.
    async fn login(&mut self, env: &Env, handle: &str) -> (StatusCode, Value) {
        let (status, body) = env
            .call(
                "POST",
                "/auth/start",
                None,
                Some(json!({"org_slug": ORG_SLUG, "handle": handle})),
            )
            .await;
        if status != StatusCode::OK {
            return (status, body);
        }
        let challenge_id = body["challenge_id"].as_str().unwrap().to_string();
        let rcr: RequestChallengeResponse =
            serde_json::from_value(body["publicKey"].clone()).unwrap();
        let assertion: PublicKeyCredential = self
            .authr
            .do_authentication(Url::parse(ORIGIN).unwrap(), rcr)
            .unwrap();
        env.call(
            "POST",
            "/auth/finish",
            None,
            Some(json!({"challenge_id": challenge_id, "credential": serde_json::to_value(&assertion).unwrap()})),
        )
        .await
    }
}

/// Seed a principal, register a device, and log in — returns (id, token, device).
async fn onboard(
    env: &Env,
    handle: &str,
    kind: PrincipalKind,
    role: &str,
) -> (PrincipalId, String, Device) {
    let pid = env.seed_principal(handle, kind, role).await;
    let token = env.issue_registration_token(pid).await;
    let mut device = Device::new();
    let (status, _) = device.register(env, handle, &token).await;
    assert_eq!(status, StatusCode::OK, "registration should succeed");
    let (status, body) = device.login(env, handle).await;
    assert_eq!(status, StatusCode::OK, "login should succeed");
    let session_token = body["token"].as_str().unwrap().to_string();
    (pid, session_token, device)
}

// ===========================================================================
// Ceremonies
// ===========================================================================

#[tokio::test]
async fn full_registration_and_authentication_ceremony() {
    let env = Env::new().await;
    let pid = env
        .seed_principal("alice", PrincipalKind::Human, roles::USER)
        .await;
    let token = env.issue_registration_token(pid).await;

    let mut device = Device::new();
    let (status, body) = device.register(&env, "alice", &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["created"], true);
    assert_eq!(body["principal_id"], pid.to_string());

    let (status, body) = device.login(&env, "alice").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["token"].is_string());
    assert_eq!(body["assurance"], "cryptographic");
}

#[tokio::test]
async fn registration_token_is_single_use() {
    let env = Env::new().await;
    let pid = env
        .seed_principal("bob", PrincipalKind::Human, roles::USER)
        .await;
    let token = env.issue_registration_token(pid).await;

    let mut d1 = Device::new();
    assert_eq!(d1.register(&env, "bob", &token).await.0, StatusCode::OK);

    // Same token again → rejected (already consumed).
    let mut d2 = Device::new();
    assert_eq!(
        d2.register(&env, "bob", &token).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn wrong_registration_token_is_rejected() {
    let env = Env::new().await;
    let pid = env
        .seed_principal("carol", PrincipalKind::Human, roles::USER)
        .await;
    let _real = env.issue_registration_token(pid).await;

    let mut device = Device::new();
    let (status, _) = device.register(&env, "carol", "WRONG-TOKEN-XX").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn second_device_attaches_to_the_same_principal() {
    let env = Env::new().await;
    let (pid, token, _first) = onboard(&env, "dave", PrincipalKind::Human, roles::USER).await;

    // Add a second device under the existing session.
    let mut second = Device::new();
    let (status, body) = second.add_to_session(&env, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["principal_id"],
        pid.to_string(),
        "second credential must attach to the same principal"
    );

    // Two credentials now, one principal.
    let creds = env.identity.list_credentials(pid).await.unwrap();
    assert_eq!(creds.len(), 2);

    // The second device can authenticate on its own.
    let (status, _) = second.login(&env, "dave").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn retried_finish_is_idempotent() {
    let env = Env::new().await;
    let pid = env
        .seed_principal("erin", PrincipalKind::Human, roles::USER)
        .await;
    let token = env.issue_registration_token(pid).await;

    let mut device = Device::new();
    let finish_body = device.registration_finish_body(&env, "erin", &token).await;

    let (s1, b1) = env
        .call("POST", "/register/finish", None, Some(finish_body.clone()))
        .await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(b1["created"], true);

    // Replaying the exact same finish must not create a duplicate.
    let (s2, b2) = env
        .call("POST", "/register/finish", None, Some(finish_body))
        .await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(b2["created"], false, "retry must be idempotent");
    assert_eq!(env.identity.list_credentials(pid).await.unwrap().len(), 1);
}

#[tokio::test]
async fn cloned_authenticator_is_detected_via_counter_regression() {
    let env = Env::new().await;
    let (pid, _token, mut device) = onboard(&env, "frank", PrincipalKind::Human, roles::USER).await;

    // Authenticate once so the ceremony has run at least once.
    assert_eq!(device.login(&env, "frank").await.0, StatusCode::OK);

    // Simulate a clone: force the counter INSIDE the stored passkey blob far
    // above the authenticator's. Verification reads the counter from the blob
    // (the source of truth), not the mirrored column, so the next assertion —
    // carrying a lower counter — is seen as a possible clone.
    let iam_core::Credential::Passkey(mut pk) =
        env.identity.list_credentials(pid).await.unwrap().remove(0);
    let mut blob: serde_json::Value = serde_json::from_slice(&pk.passkey_blob).unwrap();
    blob["cred"]["counter"] = serde_json::json!(10_000u32);
    pk.passkey_blob = serde_json::to_vec(&blob).unwrap();
    pk.sign_count = 10_000;
    env.identity
        .update_credential_after_auth(&pk)
        .await
        .unwrap();

    // The next assertion regresses relative to the stored counter → rejected.
    let (status, body) = device.login(&env, "frank").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // And it is audited as a possible compromise.
    let events = env
        .audit
        .query(&iam_store::AuditFilter {
            limit: 100,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        events.iter().any(|e| e.action == "auth.finish" && e.reason.as_deref() == Some("counter_regression")),
        "counter regression must be audited; got {body:?}"
    );
}

// ===========================================================================
// Delegation and the assurance ladder (end-to-end)
// ===========================================================================

#[tokio::test]
async fn device_acting_for_admin_cannot_exceed_the_device_ceiling() {
    let env = Env::new().await;
    let (_dev_id, device_token, _d) =
        onboard(&env, "speaker", PrincipalKind::Device, roles::DEVICE).await;
    let admin_id = env
        .seed_principal("boss", PrincipalKind::Human, roles::ADMIN)
        .await;

    // Calendar read is within the device ceiling and fine at Asserted.
    let (status, body) = env
        .call(
            "POST",
            "/authorize",
            Some(&device_token),
            Some(json!({"asserted_principal": admin_id, "action": "calendar:read"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["allowed"], true);
    assert_eq!(body["assurance"], "asserted");

    // Admin power the device lacks: denied because the DEVICE lacks it, even
    // though the asserted admin holds it — intersection, never union.
    let (_s, body) = env
        .call(
            "POST",
            "/authorize",
            Some(&device_token),
            Some(json!({"asserted_principal": admin_id, "action": "admin:manage_principals"})),
        )
        .await;
    assert_eq!(body["allowed"], false);
    assert_eq!(body["reason"], "not_permitted_for_actor");
}

#[tokio::test]
async fn asserted_assurance_is_refused_for_private_memory() {
    let env = Env::new().await;
    // The acting principal holds admin (so it structurally has private memory),
    // and asserts a human who also holds it — isolating the assurance check.
    let (_id, actor_token, _d) =
        onboard(&env, "trusted-device", PrincipalKind::Device, roles::ADMIN).await;
    let human = env
        .seed_principal("owner", PrincipalKind::Human, roles::ADMIN)
        .await;

    let (status, body) = env
        .call(
            "POST",
            "/authorize",
            Some(&actor_token),
            Some(json!({"asserted_principal": human, "action": "memory:read:private"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["allowed"], false);
    assert_eq!(body["reason"], "insufficient_assurance");

    // Shared memory, by contrast, is fine at Asserted.
    let (_s, body) = env
        .call(
            "POST",
            "/authorize",
            Some(&actor_token),
            Some(json!({"asserted_principal": human, "action": "memory:read:shared"})),
        )
        .await;
    assert_eq!(body["allowed"], true);
}

#[tokio::test]
async fn a_principal_acting_as_itself_at_cryptographic_may_read_private_memory() {
    let env = Env::new().await;
    let (_id, token, _d) = onboard(&env, "owner2", PrincipalKind::Human, roles::ADMIN).await;
    // No asserted principal → the session's own Cryptographic assurance applies.
    let (status, body) = env
        .call(
            "POST",
            "/authorize",
            Some(&token),
            Some(json!({"action": "memory:read:private"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["allowed"], true);
    assert_eq!(body["assurance"], "cryptographic");
}

#[tokio::test]
async fn cross_org_assertion_is_denied_before_policy() {
    let env = Env::new().await;
    let (_id, device_token, _d) =
        onboard(&env, "speaker2", PrincipalKind::Device, roles::DEVICE).await;

    // A principal in a DIFFERENT org.
    let other_org = Org {
        id: OrgId::new(),
        slug: "other".into(),
        name: "Other".into(),
        created_at: OffsetDateTime::now_utc(),
    };
    env.identity.create_org(&other_org).await.unwrap();
    let outsider = Principal {
        id: PrincipalId::new(),
        org_id: other_org.id,
        kind: PrincipalKind::Human,
        handle: "outsider".into(),
        display_name: "Outsider".into(),
        created_at: OffsetDateTime::now_utc(),
        disabled_at: None,
    };
    env.identity.create_principal(&outsider).await.unwrap();

    let (status, body) = env
        .call(
            "POST",
            "/authorize",
            Some(&device_token),
            Some(json!({"asserted_principal": outsider.id, "action": "calendar:read"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["allowed"], false);
    assert_eq!(body["reason"], "cross_org_assertion");
}

// ===========================================================================
// Admin lifecycle & session
// ===========================================================================

#[tokio::test]
async fn role_assignment_takes_effect_on_the_next_authorize() {
    let env = Env::new().await;
    let (admin_id, admin_token, _a) =
        onboard(&env, "admin", PrincipalKind::Human, roles::ADMIN).await;
    let _ = admin_id;
    let (target_id, target_token, _t) =
        onboard(&env, "guest-user", PrincipalKind::Human, roles::GUEST).await;

    // Guest cannot write the calendar.
    let (_s, body) = env
        .call(
            "POST",
            "/authorize",
            Some(&target_token),
            Some(json!({"action": "calendar:write"})),
        )
        .await;
    assert_eq!(body["allowed"], false);

    // Admin grants the user role.
    let (status, _) = env
        .call(
            "PUT",
            &format!("/principals/{target_id}/roles/user"),
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Now it is permitted.
    let (_s, body) = env
        .call(
            "POST",
            "/authorize",
            Some(&target_token),
            Some(json!({"action": "calendar:write"})),
        )
        .await;
    assert_eq!(body["allowed"], true);
}

#[tokio::test]
async fn revoked_credential_can_no_longer_authenticate() {
    let env = Env::new().await;
    let (pid, token, mut device) = onboard(&env, "grace", PrincipalKind::Human, roles::USER).await;

    let cred = env.identity.list_credentials(pid).await.unwrap().remove(0);
    let cred_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cred.credential_id());

    // Self-service revoke at cryptographic assurance.
    let (status, _) = env
        .call(
            "DELETE",
            &format!("/credentials/{cred_id_b64}"),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // The credential is gone, so authentication can no longer start.
    let (status, _) = device.login(&env, "grace").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn disabling_a_principal_neutralizes_live_sessions_and_enable_restores() {
    let env = Env::new().await;
    let (admin_id, admin_token, _a) =
        onboard(&env, "admin2", PrincipalKind::Human, roles::ADMIN).await;
    let _ = admin_id;
    let (victim_id, victim_token, _v) =
        onboard(&env, "victim", PrincipalKind::Human, roles::USER).await;

    // The victim's token works.
    let (status, _) = env
        .call(
            "POST",
            "/authorize",
            Some(&victim_token),
            Some(json!({"action": "calendar:read"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Admin disables them — the existing session is neutralized immediately.
    let (status, _) = env
        .call(
            "POST",
            &format!("/principals/{victim_id}/disable"),
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = env
        .call(
            "POST",
            "/authorize",
            Some(&victim_token),
            Some(json!({"action": "calendar:read"})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Re-enable restores access on the same session.
    let (status, _) = env
        .call(
            "POST",
            &format!("/principals/{victim_id}/enable"),
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = env
        .call(
            "POST",
            "/authorize",
            Some(&victim_token),
            Some(json!({"action": "calendar:read"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn logout_revokes_the_session_and_refresh_then_fails() {
    let env = Env::new().await;
    let (_id, token, _d) = onboard(&env, "heidi", PrincipalKind::Human, roles::USER).await;

    // Refresh works while the session is live.
    let (status, body) = env
        .call("POST", "/auth/refresh", None, Some(json!({"token": token})))
        .await;
    assert_eq!(status, StatusCode::OK);
    let refreshed = body["token"].as_str().unwrap().to_string();

    // Logout revokes the session.
    let (status, _) = env
        .call("POST", "/auth/logout", Some(&refreshed), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Now both the token and refresh are dead.
    let (status, _) = env
        .call(
            "POST",
            "/authorize",
            Some(&refreshed),
            Some(json!({"action": "calendar:read"})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = env
        .call(
            "POST",
            "/auth/refresh",
            None,
            Some(json!({"token": refreshed})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwks_verifies_a_freshly_issued_token() {
    let env = Env::new().await;
    let (_id, token, _d) = onboard(&env, "ivan", PrincipalKind::Human, roles::USER).await;

    let (status, jwks) = env.call("GET", "/.well-known/jwks.json", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let key = &jwks["keys"][0];
    assert_eq!(key["kty"], "OKP");
    assert_eq!(key["crv"], "Ed25519");

    // Reconstruct a verifying key from the JWK `x` and verify the token's
    // signature end-to-end (what an ecosystem service would do).
    let x_b64 = key["x"].as_str().unwrap();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x_b64)
        .unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&x.try_into().unwrap()).unwrap();

    let mut parts = token.split('.');
    let header_b64 = parts.next().unwrap();
    let payload_b64 = parts.next().unwrap();
    let sig_b64 = parts.next().unwrap();
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64)
        .unwrap();
    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
    use ed25519_dalek::Verifier;
    assert!(
        vk.verify(signing_input.as_bytes(), &signature).is_ok(),
        "JWKS key must verify the token"
    );
}

#[tokio::test]
async fn recovery_code_yields_a_registration_only_session() {
    let env = Env::new().await;
    let pid = env
        .seed_principal("judy", PrincipalKind::Human, roles::USER)
        .await;
    // Issue a recovery code directly.
    let code = iam_auth::generate_code();
    env.identity
        .insert_codes(pid, CodePurpose::Recovery, &[hash_code(&code).unwrap()])
        .await
        .unwrap();

    let (status, body) = env
        .call(
            "POST",
            "/recover",
            None,
            Some(json!({"org_slug": ORG_SLUG, "handle": "judy", "code": code})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let recovery_token = body["token"].as_str().unwrap().to_string();

    // The recovery session may add a device...
    let mut device = Device::new();
    let (status, _) = device.add_to_session(&env, &recovery_token).await;
    assert_eq!(status, StatusCode::OK);

    // ...but may NOT do anything else (recovery scope).
    let (status, _) = env
        .call(
            "POST",
            "/authorize",
            Some(&recovery_token),
            Some(json!({"action": "calendar:read"})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // And the code is single-use.
    let (status, _) = env
        .call(
            "POST",
            "/recover",
            None,
            Some(json!({"org_slug": ORG_SLUG, "handle": "judy", "code": code})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ===========================================================================
// Connections, grants, capability invocation
// ===========================================================================

/// Set up: an owner with a connection declaring one MCP tool, granted to a
/// grantee. Returns (owner_token, grantee_id, capability JSON, connection_id).
async fn setup_capability(
    env: &Env,
    owner_handle: &str,
    grantee_id: PrincipalId,
    constraints: Value,
) -> (String, Value, String) {
    let (_owner_id, owner_token, _d) =
        onboard(env, owner_handle, PrincipalKind::Human, roles::ADMIN).await;

    let (status, body) = env
        .call(
            "POST",
            "/connections",
            Some(&owner_token),
            Some(json!({
                "provider": "filesystem-mcp",
                "kind": "mcp",
                "secret": "super-secret-token",
                "capabilities": ["mcp:fs.read"],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "connection create: {body:?}");
    let connection_id = body["id"].as_str().unwrap().to_string();

    let capability = json!({"connection_id": connection_id, "operation": {"type": "mcp_tool", "name": "fs.read"}});
    let (status, body) = env
        .call(
            "POST",
            "/grants",
            Some(&owner_token),
            Some(json!({"principal_id": grantee_id, "capability": capability, "constraints": constraints})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "grant create: {body:?}");

    (owner_token, capability, connection_id)
}

#[tokio::test]
async fn delegated_device_may_invoke_a_grant_but_not_manage_grants() {
    let env = Env::new().await;
    let grantee = env
        .seed_principal("jane", PrincipalKind::Human, roles::USER)
        .await;
    let (_owner_token, capability, _conn) = setup_capability(&env, "joe", grantee, json!([])).await;

    let (_dev_id, device_token, _d) =
        onboard(&env, "gym-speaker", PrincipalKind::Device, roles::DEVICE).await;

    // Device asserts jane and invokes the granted capability → allowed at Asserted.
    let (status, body) = env
        .call(
            "POST",
            "/authorize",
            Some(&device_token),
            Some(json!({"asserted_principal": grantee, "action": "capability:invoke", "capability": capability})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["allowed"], true, "{body:?}");
    assert_eq!(body["assurance"], "asserted");

    // But the device may not create a grant — it lacks connection:manage.
    let (status, _) = env
        .call(
            "POST",
            "/grants",
            Some(&device_token),
            Some(json!({"principal_id": grantee, "capability": capability, "constraints": []})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn expired_grant_is_refused_even_though_the_role_permits_it() {
    let env = Env::new().await;
    let (owner_token, _oid, _od) = {
        let (id, token, d) = onboard(&env, "owner-exp", PrincipalKind::Human, roles::ADMIN).await;
        (token, id, d)
    };
    let grantee = env
        .seed_principal("kim", PrincipalKind::Human, roles::USER)
        .await;

    // A connection with one tool, granted with an expiry already in the past.
    let (_s, body) = env
        .call(
            "POST",
            "/connections",
            Some(&owner_token),
            Some(json!({"provider": "fs", "kind": "mcp", "secret": "s", "capabilities": ["mcp:fs.read"]})),
        )
        .await;
    let connection_id = body["id"].as_str().unwrap().to_string();
    let capability = json!({"connection_id": connection_id, "operation": {"type": "mcp_tool", "name": "fs.read"}});
    let past = (OffsetDateTime::now_utc() - time::Duration::hours(1))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let (s, body) = env
        .call(
            "POST",
            "/grants",
            Some(&owner_token),
            Some(json!({"principal_id": grantee, "capability": capability, "expires_at": past})),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{body:?}");

    // Invoking it (grantee acting as itself, cryptographic) is still refused.
    let (_gid, grantee_token, _gd) =
        onboard(&env, "kim-dev", PrincipalKind::Human, roles::USER).await;
    let _ = grantee_token;
    let (_dev, device_token, _d) =
        onboard(&env, "speaker-exp", PrincipalKind::Device, roles::DEVICE).await;
    let (status, body) = env
        .call(
            "POST",
            "/authorize",
            Some(&device_token),
            Some(json!({"asserted_principal": grantee, "action": "capability:invoke", "capability": capability})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["allowed"], false);
    assert_eq!(body["reason"], "grant_expired", "{body:?}");
}

#[tokio::test]
async fn revoking_a_connection_immediately_invalidates_its_grants() {
    let env = Env::new().await;
    let grantee = env
        .seed_principal("jane3", PrincipalKind::Human, roles::USER)
        .await;
    let (owner_token, capability, connection_id) =
        setup_capability(&env, "joe3", grantee, json!([])).await;

    let (_dev, device_token, _d) =
        onboard(&env, "speaker3", PrincipalKind::Device, roles::DEVICE).await;
    let invoke = json!({"asserted_principal": grantee, "action": "capability:invoke", "capability": capability});

    // Works before revocation.
    let (_s, body) = env
        .call(
            "POST",
            "/authorize",
            Some(&device_token),
            Some(invoke.clone()),
        )
        .await;
    assert_eq!(body["allowed"], true);

    // Revoke the connection.
    let (status, _) = env
        .call(
            "DELETE",
            &format!("/connections/{connection_id}"),
            Some(&owner_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Now the grant is dead — connection inactive.
    let (_s, body) = env
        .call("POST", "/authorize", Some(&device_token), Some(invoke))
        .await;
    assert_eq!(body["allowed"], false);
    assert_eq!(body["reason"], "connection_inactive", "{body:?}");
}

#[tokio::test]
async fn spend_and_rate_limit_constraints_are_rejected_until_backed() {
    // Spend/RateLimit caps enforce nothing today (no usage is recorded into the
    // ledgers), so the API refuses them rather than advertise a cap that does
    // nothing. Enforcement remains proven at the policy layer's unit tests.
    let env = Env::new().await;
    let grantee = env
        .seed_principal("jane4", PrincipalKind::Human, roles::USER)
        .await;
    let (_oid, owner_token, _od) = onboard(&env, "joe4", PrincipalKind::Human, roles::ADMIN).await;

    let (_s, body) = env
        .call(
            "POST",
            "/connections",
            Some(&owner_token),
            Some(json!({"provider": "anthropic", "kind": "api_key", "secret": "sk", "capabilities": ["model:claude-fable-5"]})),
        )
        .await;
    let connection_id = body["id"].as_str().unwrap().to_string();
    let capability = json!({"connection_id": connection_id, "operation": {"type": "model_endpoint", "name": "claude-fable-5"}});

    // A spend cap is rejected.
    let (status, _) = env
        .call(
            "POST",
            "/grants",
            Some(&owner_token),
            Some(json!({
                "principal_id": grantee,
                "capability": capability,
                "constraints": [{"type": "spend", "limit_minor": 1000, "period": "day"}],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // So is a rate-limit cap.
    let (status, _) = env
        .call(
            "POST",
            "/grants",
            Some(&owner_token),
            Some(json!({
                "principal_id": grantee,
                "capability": capability,
                "constraints": [{"type": "rate_limit", "max_invocations": 5, "per_seconds": 60}],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A time_window cap is accepted (stateless, actually enforced).
    let (status, _) = env
        .call(
            "POST",
            "/grants",
            Some(&owner_token),
            Some(json!({
                "principal_id": grantee,
                "capability": capability,
                "constraints": [{"type": "time_window", "start": "08:00:00", "end": "18:00:00"}],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn opaque_connection_rejects_a_scoped_grant() {
    let env = Env::new().await;
    let (owner_token, _o, _d) = {
        let (id, token, dev) = onboard(&env, "joe5", PrincipalKind::Human, roles::ADMIN).await;
        (token, id, dev)
    };
    let grantee = env
        .seed_principal("jane5", PrincipalKind::Human, roles::USER)
        .await;

    // An opaque (API key) connection declares only `*`.
    let (status, body) = env
        .call(
            "POST",
            "/connections",
            Some(&owner_token),
            Some(json!({"provider": "stripe", "kind": "api_key", "secret": "sk_live_x", "capabilities": ["*"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let connection_id = body["id"].as_str().unwrap().to_string();

    // Granting a specific MCP tool on it is rejected — not declared.
    let (status, _) = env
        .call(
            "POST",
            "/grants",
            Some(&owner_token),
            Some(json!({
                "principal_id": grantee,
                "capability": {"connection_id": connection_id, "operation": {"type": "mcp_tool", "name": "fs.read"}},
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_cannot_act_on_a_principal_in_another_org() {
    let env = Env::new().await;
    let (_aid, admin_token, _ad) =
        onboard(&env, "admin-a", PrincipalKind::Human, roles::ADMIN).await;

    // A principal in a DIFFERENT org.
    let other_org = Org {
        id: OrgId::new(),
        slug: "other-org".into(),
        name: "Other".into(),
        created_at: OffsetDateTime::now_utc(),
    };
    env.identity.create_org(&other_org).await.unwrap();
    for name in roles::ALL {
        let role = Role {
            id: RoleId::new(),
            org_id: other_org.id,
            name: name.into(),
        };
        env.identity.create_role(&role).await.unwrap();
    }
    let outsider = Principal {
        id: PrincipalId::new(),
        org_id: other_org.id,
        kind: PrincipalKind::Human,
        handle: "outsider".into(),
        display_name: "Outsider".into(),
        created_at: OffsetDateTime::now_utc(),
        disabled_at: None,
    };
    env.identity.create_principal(&outsider).await.unwrap();

    // Every admin verb on a cross-org target returns 404 (never confirms the
    // target exists, never mutates it).
    let oid = outsider.id;
    assert_eq!(
        env.call(
            "GET",
            &format!("/principals/{oid}"),
            Some(&admin_token),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        env.call(
            "PUT",
            &format!("/principals/{oid}/roles/user"),
            Some(&admin_token),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        env.call(
            "POST",
            &format!("/principals/{oid}/disable"),
            Some(&admin_token),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        env.call(
            "POST",
            &format!("/principals/{oid}/recovery-codes"),
            Some(&admin_token),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );

    // And the outsider was not disabled by the attempt.
    assert!(!env.identity.get_principal(oid).await.unwrap().is_disabled());
}

#[tokio::test]
async fn grant_over_an_expired_connection_is_refused() {
    let env = Env::new().await;
    let (_oid, owner_token, _od) =
        onboard(&env, "joe-exp", PrincipalKind::Human, roles::ADMIN).await;
    let grantee = env
        .seed_principal("jane-exp", PrincipalKind::Human, roles::USER)
        .await;

    // A connection that is already expired.
    let past = (OffsetDateTime::now_utc() - time::Duration::hours(1))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let (status, body) = env
        .call(
            "POST",
            "/connections",
            Some(&owner_token),
            Some(json!({
                "provider": "fs", "kind": "mcp", "secret": "s",
                "capabilities": ["mcp:fs.read"], "expires_at": past,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let connection_id = body["id"].as_str().unwrap().to_string();
    let capability = json!({"connection_id": connection_id, "operation": {"type": "mcp_tool", "name": "fs.read"}});

    let (status, _) = env
        .call(
            "POST",
            "/grants",
            Some(&owner_token),
            Some(json!({"principal_id": grantee, "capability": capability})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Invoking it is refused because the connection is expired — the in-memory
    // store now honors expiry exactly like Postgres.
    let (_dev, device_token, _d) =
        onboard(&env, "speaker-exp2", PrincipalKind::Device, roles::DEVICE).await;
    let (_s, body) = env
        .call(
            "POST",
            "/authorize",
            Some(&device_token),
            Some(json!({"asserted_principal": grantee, "action": "capability:invoke", "capability": capability})),
        )
        .await;
    assert_eq!(body["allowed"], false);
    assert_eq!(body["reason"], "connection_inactive", "{body:?}");
}

// ===========================================================================
// Test helpers
// ===========================================================================

/// A throwaway single-key ring for the harness.
fn test_keyring() -> KeyRing {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    let signing = SigningKey::from_bytes(&seed);
    let der = signing.to_pkcs8_der().unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(der.as_bytes());
    let json_str = json!({ "active": "t1", "keys": { "t1": b64 } }).to_string();
    let src = EnvKeySource::from_json(&json_str).unwrap();
    KeyRing::load(&src, "iam-test", "test-aud").unwrap()
}

/// The canonical permission set per role, mirroring the seed bin.
fn seed_permissions(role: &str) -> Vec<Permission> {
    let strs: &[&str] = match role {
        roles::ADMIN => return Permission::ALL.to_vec(),
        roles::USER => &[
            "calendar:read",
            "calendar:write",
            "memory:read:shared",
            "memory:read:private",
            "memory:write:shared",
            "memory:write:private",
            "spend:approve",
            "connection:read",
            "connection:manage",
            "capability:invoke",
        ],
        roles::GUEST => &["calendar:read", "memory:read:shared"],
        roles::DEVICE => &[
            "calendar:read",
            "memory:read:shared",
            "connection:read",
            "capability:invoke",
        ],
        roles::AGENT => &[
            "calendar:read",
            "calendar:write",
            "memory:read:shared",
            "memory:write:shared",
            "connection:read",
            "capability:invoke",
        ],
        _ => &[],
    };
    strs.iter().map(|s| s.parse().unwrap()).collect()
}
