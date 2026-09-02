use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{ConnectionId, OrgId, PrincipalId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionKind {
    Mcp,
    ApiKey,
    OAuth,
}

impl std::fmt::Display for ConnectionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ConnectionKind::Mcp => "mcp",
            ConnectionKind::ApiKey => "api_key",
            ConnectionKind::OAuth => "oauth",
        })
    }
}

impl std::str::FromStr for ConnectionKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mcp" => Ok(ConnectionKind::Mcp),
            "api_key" => Ok(ConnectionKind::ApiKey),
            "oauth" => Ok(ConnectionKind::OAuth),
            other => Err(format!("unknown connection kind: {other}")),
        }
    }
}

/// Refresh bookkeeping for connections whose secret can be renewed (OAuth).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RefreshState {
    /// The secret is static (API keys, most MCP credentials).
    #[default]
    None,
    Refreshable {
        #[serde(default, with = "time::serde::rfc3339::option")]
        last_refreshed_at: Option<OffsetDateTime>,
        status: Option<String>,
    },
}

/// An outbound authenticated relationship to an external system: an OAuth
/// grant, an API key, an MCP server credential.
///
/// Defining property: it is a bearer secret pointing at someone else's system.
/// This type is metadata only — the secret itself lives encrypted in
/// iam-connections and never appears in iam-core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    pub id: ConnectionId,
    /// The owning principal.
    pub principal_id: PrincipalId,
    pub org_id: OrgId,
    /// Which external system, e.g. "google", "github", "anthropic".
    pub provider: String,
    pub kind: ConnectionKind,
    /// Scopes the underlying credential holds at the provider.
    pub scopes_held: Vec<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub refresh: RefreshState,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Revoking a connection immediately invalidates every grant referencing
    /// it — grant validity is evaluated jointly, never cached.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
}

impl Connection {
    /// Usable as the target of a capability invocation right now.
    pub fn is_active(&self, now: OffsetDateTime) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|exp| exp > now)
    }
}

/// A specific invocable operation, and whether it can be granted on its own.
///
/// This is where MCP differs meaningfully from a raw API key: an MCP server
/// *describes* its capabilities, so `filesystem.read` is grantable
/// independently of `filesystem.write`. An API key is opaque — scopes, if any,
/// are enforced on the far side — so it is grantable only as a whole.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CapabilityOperation {
    /// An MCP tool, independently scopable. Canonical form `mcp:<name>`.
    McpTool { name: String },
    /// A model endpoint, independently scopable and metered. `model:<name>`.
    ModelEndpoint { name: String },
    /// The whole opaque surface behind an API key. Canonical form `*`.
    Opaque,
}

impl CapabilityOperation {
    pub fn independently_scopable(&self) -> bool {
        match self {
            CapabilityOperation::McpTool { .. } | CapabilityOperation::ModelEndpoint { .. } => true,
            CapabilityOperation::Opaque => false,
        }
    }
}

impl std::fmt::Display for CapabilityOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapabilityOperation::McpTool { name } => write!(f, "mcp:{name}"),
            CapabilityOperation::ModelEndpoint { name } => write!(f, "model:{name}"),
            CapabilityOperation::Opaque => f.write_str("*"),
        }
    }
}

impl std::str::FromStr for CapabilityOperation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "*" {
            return Ok(CapabilityOperation::Opaque);
        }
        if let Some(name) = s.strip_prefix("mcp:") {
            if name.is_empty() {
                return Err("mcp operation requires a tool name".into());
            }
            return Ok(CapabilityOperation::McpTool { name: name.to_string() });
        }
        if let Some(name) = s.strip_prefix("model:") {
            if name.is_empty() {
                return Err("model operation requires an endpoint name".into());
            }
            return Ok(CapabilityOperation::ModelEndpoint { name: name.to_string() });
        }
        Err(format!("unknown capability operation: {s}"))
    }
}

/// A specific invocable operation on a connection: an MCP tool, a model
/// endpoint, an API operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Capability {
    pub connection_id: ConnectionId,
    pub operation: CapabilityOperation,
}

/// Stable designation of a capability, used by grants and `/authorize`.
/// Identical in shape to [`Capability`]; the alias keeps both vocabulary words
/// honest without duplicating the type.
pub type CapabilityRef = Capability;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_operation_round_trips() {
        let ops = [
            CapabilityOperation::McpTool { name: "filesystem.read".into() },
            CapabilityOperation::ModelEndpoint { name: "claude-fable-5".into() },
            CapabilityOperation::Opaque,
        ];
        for op in ops {
            let s = op.to_string();
            assert_eq!(s.parse::<CapabilityOperation>().unwrap(), op, "{s}");
        }
    }

    #[test]
    fn scopability_follows_the_variant() {
        assert!(CapabilityOperation::McpTool { name: "x".into() }.independently_scopable());
        assert!(CapabilityOperation::ModelEndpoint { name: "x".into() }.independently_scopable());
        assert!(!CapabilityOperation::Opaque.independently_scopable());
    }
}
