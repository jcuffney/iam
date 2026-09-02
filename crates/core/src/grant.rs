use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, Time};

use crate::{CapabilityRef, GrantId, PrincipalId};

// Serialize `TimeWindow` bounds as plain `"HH:MM:SS"` strings. The `time`
// crate's default human-readable format demands a subsecond (`HH:MM:SS.sss`),
// which is a poor API; this keeps the wire and jsonb forms clean.
time::serde::format_description!(hms, Time, "[hour]:[minute]:[second]");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpendPeriod {
    Day,
    Month,
}

/// A condition a grant imposes on invocation. Evaluated by iam-policy at
/// decision time, before the invocation is authorized — never after.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Constraint {
    RateLimit {
        max_invocations: u32,
        per_seconds: u64,
    },
    /// Allowed wall-clock window, evaluated in UTC. Bounds are `"HH:MM:SS"`.
    TimeWindow {
        #[serde(with = "hms")]
        start: Time,
        #[serde(with = "hms")]
        end: Time,
    },
    /// Usage cost cap for metered capabilities (model endpoints). `limit_minor`
    /// is in minor currency units. This is the seam the wallet/escrow layer
    /// plugs into later; evaluation goes through the `SpendLedger` trait.
    Spend {
        limit_minor: u64,
        period: SpendPeriod,
    },
}

/// The binding iam-policy actually evaluates: a principal may invoke a
/// capability, under constraints, until expiry or revocation.
///
/// Object-capability semantics: the grant both designates the resource and
/// authorizes its use, and revocation — of the grant or of the connection
/// behind it — is immediate and total.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub id: GrantId,
    /// The grantee.
    pub principal: PrincipalId,
    pub capability: CapabilityRef,
    pub constraints: Vec<Constraint>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub granted_by: PrincipalId,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
}

impl Grant {
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at.is_some_and(|exp| exp <= now)
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}
