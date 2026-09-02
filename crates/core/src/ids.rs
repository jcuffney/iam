use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl From<Uuid> for $name {
            fn from(id: Uuid) -> Self {
                Self(id)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self(Uuid::parse_str(s)?))
            }
        }
    };
}

id_type!(
    /// Identifies an [`crate::Org`], the root tenant.
    OrgId
);
id_type!(
    /// Identifies a [`crate::Principal`] — human, device, or agent.
    PrincipalId
);
id_type!(
    /// Identifies a [`crate::Role`] within an org.
    RoleId
);
id_type!(
    /// Identifies a [`crate::Connection`] to an external system.
    ConnectionId
);
id_type!(
    /// Identifies a [`crate::Grant`] binding a principal to a capability.
    GrantId
);
