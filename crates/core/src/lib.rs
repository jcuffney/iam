//! Domain types for the iam service.
//!
//! This crate is the shared vocabulary: identifiers, principals, credentials,
//! permissions, assurance, audit events, and the outbound-connection model
//! (connections, capabilities, grants, constraints). It holds no behavior
//! beyond what the types themselves imply, and depends on nothing but
//! serde/uuid/time so every other crate can build on it without dragging in
//! IO, crypto, or HTTP.

mod assurance;
mod audit;
mod connection;
mod credential;
mod grant;
mod ids;
mod org;
mod permission;
mod principal;
mod role;

pub use assurance::Assurance;
pub use audit::{AuditDecision, AuditEvent};
pub use connection::{Capability, CapabilityOperation, CapabilityRef, Connection, ConnectionKind, RefreshState};
pub use credential::{Credential, CredentialKind, PasskeyCredential};
pub use grant::{Constraint, Grant, SpendPeriod};
pub use ids::{ConnectionId, GrantId, OrgId, PrincipalId, RoleId};
pub use org::Org;
pub use permission::{
    AdminAction, CalendarAction, CapabilityAction, ConnectionAction, MemoryAction, Permission, PermissionParseError,
    PermissionSet, Sensitivity, SpendAction,
};
pub use principal::{Principal, PrincipalKind};
pub use role::{Role, roles};
