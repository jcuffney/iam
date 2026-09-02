use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::OrgId;

/// The root tenant. A household or a company; the same structure serves both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Org {
    pub id: OrgId,
    pub slug: String,
    pub name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
