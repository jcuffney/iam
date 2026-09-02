//! One-time codes: recovery codes and registration tokens.
//!
//! Both are the same primitive — a high-entropy secret shown once and stored
//! only as an argon2id hash. Recovery codes let a principal who has lost every
//! device get back in; a registration token authorizes binding the *first*
//! credential to a freshly created principal (so a handle alone cannot be
//! claimed by a stranger).

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as B64;

use crate::error::AuthError;

/// Crockford base32 alphabet — no ambiguous characters, case-insensitive on the
/// way back in.
const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// How many recovery codes to mint at once.
pub const RECOVERY_CODE_COUNT: usize = 10;

/// Generate a single high-entropy code, formatted in groups for legibility
/// (e.g. `K3M9-QP7X-2R5T`). ~15 crockford chars ≈ 75 bits.
pub fn generate_code() -> String {
    let mut raw = [0u8; 10];
    getrandom::fill(&mut raw).expect("system RNG");
    let mut out = String::with_capacity(18);
    for (i, b) in raw.iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(CROCKFORD[(*b as usize) % CROCKFORD.len()] as char);
    }
    out
}

/// Generate a batch of recovery codes.
pub fn generate_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODE_COUNT).map(|_| generate_code()).collect()
}

/// Generate a registration token — the same shape, distinct purpose.
pub fn generate_registration_token() -> String {
    generate_code()
}

/// Normalize a code for comparison: uppercase, strip separators and spaces.
/// Users may retype codes with different casing or omit the dashes.
fn normalize(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(|c| c.to_uppercase())
        .collect()
}

/// Hash a code for storage (argon2id PHC string). argon2 0.6 generates the
/// salt internally.
pub fn hash_code(code: &str) -> Result<String, AuthError> {
    let normalized = normalize(code);
    let hash = Argon2::default()
        .hash_password(normalized.as_bytes())
        .map_err(|e| AuthError::Config(format!("argon2 hashing failed: {e}")))?;
    Ok(hash.to_string())
}

/// Verify a presented code against a stored PHC hash.
pub fn verify_code(code: &str, stored_hash: &str) -> bool {
    let normalized = normalize(code);
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(normalized.as_bytes(), &parsed)
        .is_ok()
}

/// Encode arbitrary bytes as a compact token (used where a URL-safe opaque
/// string is handy). Kept here so callers do not each pick a base64 flavor.
pub fn encode_opaque(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_round_trips_through_hash_and_verify() {
        let code = generate_code();
        let hash = hash_code(&code).unwrap();
        assert!(verify_code(&code, &hash));
    }

    #[test]
    fn verification_is_case_and_separator_insensitive() {
        let code = "K3M9-QP7X-2R5T";
        let hash = hash_code(code).unwrap();
        assert!(verify_code("k3m9qp7x2r5t", &hash));
        assert!(verify_code("K3M9 QP7X 2R5T", &hash));
    }

    #[test]
    fn wrong_code_does_not_verify() {
        let hash = hash_code(&generate_code()).unwrap();
        assert!(!verify_code(&generate_code(), &hash));
    }

    #[test]
    fn each_code_hash_is_unique_due_to_salting() {
        let code = "SAME-CODE-HERE";
        assert_ne!(hash_code(code).unwrap(), hash_code(code).unwrap());
    }

    #[test]
    fn batch_generates_the_expected_count_all_distinct() {
        let codes = generate_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), RECOVERY_CODE_COUNT);
    }

    #[test]
    fn garbage_hash_string_fails_closed() {
        assert!(!verify_code("anything", "not-a-phc-string"));
    }
}
