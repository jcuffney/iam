use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::PrincipalId;

/// Discriminator for credential storage. `Wallet` will join this list; nothing
/// else should need to change shape when it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialKind {
    Passkey,
}

impl std::fmt::Display for CredentialKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CredentialKind::Passkey => "passkey",
        })
    }
}

impl std::str::FromStr for CredentialKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "passkey" => Ok(CredentialKind::Passkey),
            other => Err(format!("unknown credential kind: {other}")),
        }
    }
}

/// A registered authenticator bound to a principal.
///
/// Modeled as an enum so a `Wallet` public key can later sit beside a passkey
/// on the same principal as an alternative credential type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Credential {
    Passkey(PasskeyCredential),
}

impl Credential {
    pub fn credential_id(&self) -> &[u8] {
        match self {
            Credential::Passkey(p) => &p.credential_id,
        }
    }

    pub fn principal_id(&self) -> PrincipalId {
        match self {
            Credential::Passkey(p) => p.principal_id,
        }
    }

    pub fn kind(&self) -> CredentialKind {
        match self {
            Credential::Passkey(_) => CredentialKind::Passkey,
        }
    }

    pub fn nickname(&self) -> Option<&str> {
        match self {
            Credential::Passkey(p) => p.nickname.as_deref(),
        }
    }
}

/// A WebAuthn passkey.
///
/// `passkey_blob` is the serialized webauthn-rs `Passkey` — the verification
/// source of truth, opaque to this crate (iam-auth owns the serialization).
/// The remaining fields mirror what callers query without deserializing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyCredential {
    /// Raw WebAuthn credential ID as returned by the authenticator.
    pub credential_id: Vec<u8>,
    pub principal_id: PrincipalId,
    pub passkey_blob: Vec<u8>,
    /// Signature counter; regression signals a cloned authenticator. Synced
    /// passkeys legitimately report 0 forever.
    pub sign_count: u32,
    pub transports: Vec<String>,
    /// None in the plain-passkey (none-attestation) flow; only attested
    /// registration retains the authenticator model identifier.
    pub aaguid: Option<Uuid>,
    pub nickname: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<OffsetDateTime>,
}
