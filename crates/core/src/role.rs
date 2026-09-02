use serde::{Deserialize, Serialize};

use crate::{OrgId, RoleId};

/// A named bundle of permissions, scoped to an org. A principal may hold
/// several; its permission set is the union of its roles' permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub org_id: OrgId,
    pub name: String,
}

/// The seeded role names. Constants so seed code and tests cannot drift.
pub mod roles {
    pub const ADMIN: &str = "admin";
    pub const USER: &str = "user";
    pub const GUEST: &str = "guest";
    pub const DEVICE: &str = "device";
    pub const AGENT: &str = "agent";

    pub const ALL: [&str; 5] = [ADMIN, USER, GUEST, DEVICE, AGENT];
}
