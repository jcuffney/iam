//! Persistence-shaped types the stores exchange that are not part of the domain
//! vocabulary in iam-core (they describe ephemeral state and query shapes).

use iam_core::{Assurance, AuditDecision, OrgId, PrincipalId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Which ceremony a challenge belongs to. The mode and the target principal
/// live server-side in the challenge record so the client can never redirect a
/// finish to a different principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeMode {
    /// Binding the first credential to a credential-less principal.
    RegisterFirst,
    /// Adding another credential to an already-authenticated principal.
    RegisterDevice,
    /// Authentication assertion.
    Auth,
}

/// An in-flight WebAuthn ceremony. Consumed exactly once; rejected past
/// `expires_at` regardless of whether TTL has swept it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRecord {
    pub challenge_id: String,
    pub mode: ChallengeMode,
    pub principal_id: PrincipalId,
    pub org_id: OrgId,
    /// Serialized webauthn-rs ceremony state (opaque here).
    pub state_blob: Vec<u8>,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// What a session is scoped to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionScope {
    /// A normal session: authorize, use connections, etc.
    Full,
    /// A recovery session: may ONLY add a new credential
    /// (`/register/device/*`). Everything else is refused.
    CredentialRegistrationOnly,
}

impl SessionScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionScope::Full => "full",
            SessionScope::CredentialRegistrationOnly => "credential_registration_only",
        }
    }
}

/// An active session. The revocable authority behind a token: a token is only
/// valid while its `session_id` resolves to a live, unexpired record here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub principal_id: PrincipalId,
    pub org_id: OrgId,
    pub assurance: Assurance,
    pub scope: SessionScope,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

impl SessionRecord {
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at <= now
    }
}

/// Purpose discriminator for one-time codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodePurpose {
    Recovery,
    Registration,
}

impl CodePurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            CodePurpose::Recovery => "recovery",
            CodePurpose::Registration => "registration",
        }
    }
}

/// A stored one-time code the caller must verify (the store holds only hashes;
/// argon2 verification lives in iam-auth, called from the api layer).
#[derive(Debug, Clone)]
pub struct StoredCode {
    pub id: uuid::Uuid,
    pub code_hash: String,
}

/// Filter for audit queries. All fields optional; `limit` caps the result.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub org_id: Option<OrgId>,
    pub actor_id: Option<PrincipalId>,
    pub action: Option<String>,
    pub decision: Option<AuditDecision>,
    pub from: Option<OffsetDateTime>,
    pub to: Option<OffsetDateTime>,
    pub limit: i64,
}

impl AuditFilter {
    pub fn new() -> Self {
        Self { limit: 100, ..Default::default() }
    }
}
