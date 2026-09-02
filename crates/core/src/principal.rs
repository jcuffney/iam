use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{OrgId, PrincipalId};

/// What kind of thing a principal is. All three are first-class: a device or an
/// agent is not a second-class shadow of a human account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrincipalKind {
    Human,
    Device,
    Agent,
}

impl std::fmt::Display for PrincipalKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PrincipalKind::Human => "human",
            PrincipalKind::Device => "device",
            PrincipalKind::Agent => "agent",
        })
    }
}

impl std::str::FromStr for PrincipalKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "human" => Ok(PrincipalKind::Human),
            "device" => Ok(PrincipalKind::Device),
            "agent" => Ok(PrincipalKind::Agent),
            other => Err(format!("unknown principal kind: {other}")),
        }
    }
}

/// Anything that can act. Belongs to exactly one org and may hold many
/// credentials — adding a second device never means creating a second account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub id: PrincipalId,
    pub org_id: OrgId,
    pub kind: PrincipalKind,
    /// Unique within the org; used to start authentication.
    pub handle: String,
    pub display_name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// A disabled principal cannot authenticate, and live sessions are refused
    /// at the extractor, so disabling takes effect immediately.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub disabled_at: Option<OffsetDateTime>,
}

impl Principal {
    pub fn is_disabled(&self) -> bool {
        self.disabled_at.is_some()
    }
}
