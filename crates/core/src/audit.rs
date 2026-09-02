use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{Assurance, OrgId, PrincipalId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditDecision {
    Allow,
    Deny,
}

impl std::fmt::Display for AuditDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AuditDecision::Allow => "allow",
            AuditDecision::Deny => "deny",
        })
    }
}

impl std::str::FromStr for AuditDecision {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow" => Ok(AuditDecision::Allow),
            "deny" => Ok(AuditDecision::Deny),
            other => Err(format!("unknown audit decision: {other}")),
        }
    }
}

/// What actually happened. Append-only: the store exposes no update or delete,
/// and the database refuses them with a trigger.
///
/// When a device acts on an asserted human's behalf, `actor_id` is the device
/// (the authenticated principal) and `asserted_id` is the human — both
/// identities, always.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub org_id: OrgId,
    pub actor_id: PrincipalId,
    pub asserted_id: Option<PrincipalId>,
    /// A permission string (`memory:read:private`), a capability reference, or
    /// a lifecycle action (`auth.finish`, `principal.create`, …).
    pub action: String,
    pub decision: AuditDecision,
    /// Present for authorization decisions and successful authentications;
    /// absent where assurance is not meaningful (e.g. a failed challenge).
    pub assurance: Option<Assurance>,
    pub reason: Option<String>,
    pub ip: Option<IpAddr>,
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
}
