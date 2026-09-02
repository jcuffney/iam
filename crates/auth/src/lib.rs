//! Authentication primitives for the iam service: WebAuthn ceremonies, session
//! token signing with rotatable keys, and one-time recovery/registration codes.
//!
//! This crate performs cryptographic operations but holds no persistence. It
//! turns webauthn-rs and jsonwebtoken into iam-core-shaped inputs and outputs
//! so the store and api crates never touch those libraries directly.

mod error;
mod recovery;
mod tokens;
mod webauthn;

pub use error::AuthError;
pub use recovery::{
    RECOVERY_CODE_COUNT, encode_opaque, generate_code, generate_recovery_codes, generate_registration_token, hash_code,
    verify_code,
};
pub use tokens::{Claims, EnvKeySource, KeyRing, SigningKeySource};
pub use webauthn::{RegisteredCredential, VerifiedAssertion, WebauthnService};

// Re-export the webauthn-rs request/response types the api layer must accept
// and return in ceremony bodies, so it depends on this crate rather than
// webauthn-rs directly for them.
pub mod ceremony {
    pub use webauthn_rs::prelude::{
        CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse,
    };
}
