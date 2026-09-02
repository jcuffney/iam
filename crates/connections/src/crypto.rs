//! AES-256-GCM envelope encryption for connection secrets.
//!
//! Each secret is sealed under a per-connection random 96-bit nonce with the
//! service's connections encryption key. The key is distinct from anything the
//! identity store holds — that separation is the entire point of this crate.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::error::ConnectionsError;

/// The connections encryption key. 32 bytes for AES-256.
#[derive(Clone)]
pub struct EncryptionKey {
    cipher: Aes256Gcm,
}

/// A sealed secret: ciphertext plus the nonce it was sealed under.
#[derive(Debug, Clone)]
pub struct Sealed {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl EncryptionKey {
    /// Build from raw 32 key bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectionsError> {
        if bytes.len() != 32 {
            return Err(ConnectionsError::InvalidKey(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let cipher = Aes256Gcm::new_from_slice(bytes)
            .map_err(|e| ConnectionsError::InvalidKey(e.to_string()))?;
        Ok(Self { cipher })
    }

    /// Build from a base64-encoded 32-byte key (env / Secrets Manager form).
    pub fn from_base64(b64: &str) -> Result<Self, ConnectionsError> {
        let bytes = B64
            .decode(b64.trim())
            .map_err(|e| ConnectionsError::InvalidKey(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    /// Seal a plaintext secret under a fresh random nonce.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Sealed, ConnectionsError> {
        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes).map_err(|_| ConnectionsError::Encryption)?;
        let nonce = Nonce::<Aes256Gcm>::from(nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| ConnectionsError::Encryption)?;
        Ok(Sealed {
            ciphertext,
            nonce: nonce_bytes.to_vec(),
        })
    }

    /// Open a sealed secret.
    pub fn open(&self, sealed: &Sealed) -> Result<Vec<u8>, ConnectionsError> {
        let nonce_bytes: [u8; 12] = sealed
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| ConnectionsError::Encryption)?;
        let nonce = Nonce::<Aes256Gcm>::from(nonce_bytes);
        self.cipher
            .decrypt(&nonce, sealed.ciphertext.as_ref())
            .map_err(|_| ConnectionsError::Encryption)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> EncryptionKey {
        EncryptionKey::from_bytes(&[7u8; 32]).unwrap()
    }

    #[test]
    fn seal_open_round_trips() {
        let k = key();
        let sealed = k.seal(b"ya29.super-secret-token").unwrap();
        assert_eq!(k.open(&sealed).unwrap(), b"ya29.super-secret-token");
    }

    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        let k = key();
        let a = k.seal(b"same").unwrap();
        let b = k.seal(b"same").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn wrong_key_cannot_open() {
        let sealed = key().seal(b"secret").unwrap();
        let other = EncryptionKey::from_bytes(&[9u8; 32]).unwrap();
        assert!(other.open(&sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let k = key();
        let mut sealed = k.seal(b"secret").unwrap();
        sealed.ciphertext[0] ^= 0xff;
        assert!(k.open(&sealed).is_err());
    }

    #[test]
    fn wrong_key_length_is_rejected() {
        assert!(EncryptionKey::from_bytes(&[0u8; 16]).is_err());
    }
}
