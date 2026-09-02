use std::collections::BTreeSet;

use serde::{Deserialize, Serialize, de};

use crate::Assurance;

/// The set type policy operates on. `BTreeSet` so intersections are cheap and
/// iteration order is deterministic.
pub type PermissionSet = BTreeSet<Permission>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalendarAction {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemoryAction {
    Read,
    Write,
}

/// Sensitivity dimension for memory. Private memory demands cryptographic
/// proof of identity, not a device's say-so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sensitivity {
    Shared,
    Private,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SpendAction {
    Approve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdminAction {
    ManagePrincipals,
    ManageRoles,
    ReadAudit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConnectionAction {
    /// May use an existing connection.
    Read,
    /// May create, modify, or revoke one — including grants over its
    /// capabilities.
    Manage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapabilityAction {
    /// May invoke a granted capability.
    Invoke,
}

/// Everything a role can permit, grouped by resource. Deliberately an enum,
/// not free-form strings: an unknown permission is a load error, not a silent
/// no-op.
///
/// Canonical string forms (`Display`/`FromStr`, also the serde and database
/// representation): `calendar:read`, `memory:write:private`, `spend:approve`,
/// `admin:manage_roles`, `connection:manage`, `capability:invoke`, …
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Permission {
    Calendar(CalendarAction),
    Memory(MemoryAction, Sensitivity),
    Spend(SpendAction),
    Admin(AdminAction),
    Connection(ConnectionAction),
    Capability(CapabilityAction),
}

impl Permission {
    /// Every concrete permission. Tests iterate this to prove the assurance
    /// ladder and intersection rule exhaustively; `exhaustive_guard` below
    /// breaks the build if a variant is added without updating it.
    pub const ALL: [Permission; 13] = [
        Permission::Calendar(CalendarAction::Read),
        Permission::Calendar(CalendarAction::Write),
        Permission::Memory(MemoryAction::Read, Sensitivity::Shared),
        Permission::Memory(MemoryAction::Read, Sensitivity::Private),
        Permission::Memory(MemoryAction::Write, Sensitivity::Shared),
        Permission::Memory(MemoryAction::Write, Sensitivity::Private),
        Permission::Spend(SpendAction::Approve),
        Permission::Admin(AdminAction::ManagePrincipals),
        Permission::Admin(AdminAction::ManageRoles),
        Permission::Admin(AdminAction::ReadAudit),
        Permission::Connection(ConnectionAction::Read),
        Permission::Connection(ConnectionAction::Manage),
        Permission::Capability(CapabilityAction::Invoke),
    ];

    /// The minimum assurance a decision must carry for this permission.
    ///
    /// Reading a calendar is fine on a device's assertion; reading private
    /// memory, approving spend, administering the org, or managing a
    /// connection requires the principal's own credential to have signed.
    pub fn required_assurance(&self) -> Assurance {
        match self {
            Permission::Calendar(_) => Assurance::Asserted,
            Permission::Memory(_, Sensitivity::Shared) => Assurance::Asserted,
            Permission::Memory(_, Sensitivity::Private) => Assurance::Cryptographic,
            Permission::Spend(_) => Assurance::Cryptographic,
            Permission::Admin(_) => Assurance::Cryptographic,
            Permission::Connection(ConnectionAction::Read) => Assurance::Asserted,
            Permission::Connection(ConnectionAction::Manage) => Assurance::Cryptographic,
            Permission::Capability(CapabilityAction::Invoke) => Assurance::Asserted,
        }
    }
}

/// Compile-time completeness check: a new variant fails this match (no
/// wildcard) until `Permission::ALL` and the string mappings are updated.
#[allow(dead_code)]
fn exhaustive_guard(p: Permission) {
    match p {
        Permission::Calendar(CalendarAction::Read) => (),
        Permission::Calendar(CalendarAction::Write) => (),
        Permission::Memory(MemoryAction::Read, Sensitivity::Shared) => (),
        Permission::Memory(MemoryAction::Read, Sensitivity::Private) => (),
        Permission::Memory(MemoryAction::Write, Sensitivity::Shared) => (),
        Permission::Memory(MemoryAction::Write, Sensitivity::Private) => (),
        Permission::Spend(SpendAction::Approve) => (),
        Permission::Admin(AdminAction::ManagePrincipals) => (),
        Permission::Admin(AdminAction::ManageRoles) => (),
        Permission::Admin(AdminAction::ReadAudit) => (),
        Permission::Connection(ConnectionAction::Read) => (),
        Permission::Connection(ConnectionAction::Manage) => (),
        Permission::Capability(CapabilityAction::Invoke) => (),
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Permission::Calendar(CalendarAction::Read) => "calendar:read",
            Permission::Calendar(CalendarAction::Write) => "calendar:write",
            Permission::Memory(MemoryAction::Read, Sensitivity::Shared) => "memory:read:shared",
            Permission::Memory(MemoryAction::Read, Sensitivity::Private) => "memory:read:private",
            Permission::Memory(MemoryAction::Write, Sensitivity::Shared) => "memory:write:shared",
            Permission::Memory(MemoryAction::Write, Sensitivity::Private) => "memory:write:private",
            Permission::Spend(SpendAction::Approve) => "spend:approve",
            Permission::Admin(AdminAction::ManagePrincipals) => "admin:manage_principals",
            Permission::Admin(AdminAction::ManageRoles) => "admin:manage_roles",
            Permission::Admin(AdminAction::ReadAudit) => "admin:read_audit",
            Permission::Connection(ConnectionAction::Read) => "connection:read",
            Permission::Connection(ConnectionAction::Manage) => "connection:manage",
            Permission::Capability(CapabilityAction::Invoke) => "capability:invoke",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionParseError(pub String);

impl std::fmt::Display for PermissionParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown permission: {}", self.0)
    }
}

impl std::error::Error for PermissionParseError {}

impl std::str::FromStr for Permission {
    type Err = PermissionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let p = match s {
            "calendar:read" => Permission::Calendar(CalendarAction::Read),
            "calendar:write" => Permission::Calendar(CalendarAction::Write),
            "memory:read:shared" => Permission::Memory(MemoryAction::Read, Sensitivity::Shared),
            "memory:read:private" => Permission::Memory(MemoryAction::Read, Sensitivity::Private),
            "memory:write:shared" => Permission::Memory(MemoryAction::Write, Sensitivity::Shared),
            "memory:write:private" => Permission::Memory(MemoryAction::Write, Sensitivity::Private),
            "spend:approve" => Permission::Spend(SpendAction::Approve),
            "admin:manage_principals" => Permission::Admin(AdminAction::ManagePrincipals),
            "admin:manage_roles" => Permission::Admin(AdminAction::ManageRoles),
            "admin:read_audit" => Permission::Admin(AdminAction::ReadAudit),
            "connection:read" => Permission::Connection(ConnectionAction::Read),
            "connection:manage" => Permission::Connection(ConnectionAction::Manage),
            "capability:invoke" => Permission::Capability(CapabilityAction::Invoke),
            other => return Err(PermissionParseError(other.to_string())),
        };
        Ok(p)
    }
}

impl Serialize for Permission {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Permission {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_permission_round_trips_through_its_string_form() {
        for p in Permission::ALL {
            let s = p.to_string();
            assert_eq!(s.parse::<Permission>().unwrap(), p, "{s}");
        }
    }

    #[test]
    fn all_has_no_duplicates() {
        let set: PermissionSet = Permission::ALL.into_iter().collect();
        assert_eq!(set.len(), Permission::ALL.len());
    }

    #[test]
    fn unknown_permission_is_an_error_not_a_default() {
        assert!("calendar:destroy".parse::<Permission>().is_err());
        assert!("".parse::<Permission>().is_err());
    }

    #[test]
    fn serde_uses_the_canonical_string_form() {
        let p = Permission::Memory(MemoryAction::Read, Sensitivity::Private);
        // serde_json is not a core dependency; serde_test-style manual check
        // via the Display path is sufficient because Serialize delegates to it.
        assert_eq!(p.to_string(), "memory:read:private");
    }
}
