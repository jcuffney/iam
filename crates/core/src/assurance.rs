use serde::{Deserialize, Serialize};

/// How strongly the acting identity was established for a request.
///
/// Declaration order matters: the derived `Ord` gives
/// `Asserted < Cryptographic`, which is exactly the ladder policy checks
/// against a permission's [`crate::Permission::required_assurance`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Assurance {
    /// A device vouched for the identity (e.g. voice recognition). An
    /// assertion, not proof.
    Asserted,
    /// The principal's own credential signed the request.
    Cryptographic,
}

impl std::fmt::Display for Assurance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Assurance::Asserted => "asserted",
            Assurance::Cryptographic => "cryptographic",
        })
    }
}

impl std::str::FromStr for Assurance {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "asserted" => Ok(Assurance::Asserted),
            "cryptographic" => Ok(Assurance::Cryptographic),
            other => Err(format!("unknown assurance level: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asserted_is_below_cryptographic() {
        assert!(Assurance::Asserted < Assurance::Cryptographic);
        assert!(Assurance::Cryptographic >= Assurance::Asserted);
        assert!(Assurance::Asserted >= Assurance::Asserted);
    }
}
