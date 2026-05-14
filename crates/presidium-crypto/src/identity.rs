//! Identity management: Ed25519 signing key, DID, BIP39 seed phrase.
//!
//! This module provides the foundational identity primitive for Presidium:
//! an Ed25519 keypair tied to a W3C-style Decentralized Identifier (DID),
//! backed by a BIP39 mnemonic seed phrase for human-readable backup and recovery.

use bip39::Mnemonic;
use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;

/// Errors that can occur during identity operations.
#[derive(Error, Debug)]
pub enum IdentityError {
    /// The seed phrase has the wrong word count (expected 24).
    #[error("invalid seed phrase: expected 24 words, got {0}")]
    InvalidSeedPhrase(usize),
}

/// A Presidium identity: Ed25519 signing key + DID.
///
/// Holds the long-term Ed25519 keypair used for signing and authentication,
/// along with the corresponding Decentralized Identifier (DID).
///
/// # Security
///
/// The underlying [`SigningKey`] from `ed25519-dalek` implements `ZeroizeOnDrop`,
/// ensuring secret key material is overwritten when the `Identity` is dropped.
///
/// # Example
///
/// ```ignore
/// use presidium_crypto::identity::Identity;
/// let (identity, mnemonic) = Identity::generate();
/// println!("DID: {}", identity.did());
/// println!("Seed phrase: {}", mnemonic.to_phrase());
/// ```
#[derive(Clone)]
pub struct Identity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    did: String,
}

impl Identity {
    /// Generate a new random identity, returning the identity and a 24-word BIP39 mnemonic.
    ///
    /// Uses [`OsRng`] exclusively for entropy — no `thread_rng` or other
    /// predictable sources. The mnemonic can be used to recover the identity
    /// later via [`Identity::recover`].
    ///
    /// This function is infallible: 32 bytes of entropy always maps to a valid
    /// 24-word mnemonic per BIP39, and [`SigningKey::from_bytes`] accepts any
    /// 32-byte input.
    ///
    /// # Panics
    ///
    /// Will panic if the OS entropy source fails or if `Mnemonic::from_entropy`
    /// rejects 32 bytes of entropy (both are theoretically impossible per BIP39 spec).
    #[must_use]
    pub fn generate() -> (Self, Mnemonic) {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        // SAFETY: 32 bytes of entropy always maps to a valid 24-word mnemonic per BIP39.
        // The only way this can fail is a bug in the `bip39` crate.
        let Ok(mnemonic) = Mnemonic::from_entropy(&entropy) else {
            unreachable!("32-byte entropy must produce a valid 24-word mnemonic")
        };
        let identity = Self::from_mnemonic_internal(&mnemonic);
        (identity, mnemonic)
    }

    /// Recover an identity from a BIP39 mnemonic (must be exactly 24 words).
    ///
    /// Derives the Ed25519 signing key from the first 32 bytes of the BIP39 seed
    /// (with an empty passphrase) and reconstructs the DID from the verifying key.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidSeedPhrase`] if the mnemonic does not
    /// contain exactly 24 words. Shorter mnemonics (12 or 15 words) are rejected
    /// because Presidium requires 256 bits of entropy for security.
    pub fn recover(mnemonic: &Mnemonic) -> Result<Self, IdentityError> {
        let wc = mnemonic.word_count();
        if wc != 24 {
            return Err(IdentityError::InvalidSeedPhrase(wc));
        }
        Ok(Self::from_mnemonic_internal(mnemonic))
    }

    /// Return the public (verifying) key bytes (Ed25519, 32 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Return the DID string in the format `did:presidium:<base58-pubkey>`.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Access the full signing key (for use in X3DH, Double Ratchet, etc.).
    #[must_use]
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Access the verifying (public) key.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Internal helper: derive identity from a mnemonic (caller validates word count).
    fn from_mnemonic_internal(mnemonic: &Mnemonic) -> Self {
        let seed = mnemonic.to_seed("");
        let mut sk_bytes = [0u8; SECRET_KEY_LENGTH];
        sk_bytes.copy_from_slice(&seed[..SECRET_KEY_LENGTH]);
        let signing_key = SigningKey::from_bytes(&sk_bytes);
        let verifying_key = signing_key.verifying_key();
        let did = Self::build_did(&verifying_key);
        Self {
            signing_key,
            verifying_key,
            did,
        }
    }

    /// Build the DID URI from a verifying key.
    fn build_did(vk: &VerifyingKey) -> String {
        format!(
            "did:presidium:{}",
            bs58::encode(vk.to_bytes()).into_string()
        )
    }
}

/// Parse a DID string and extract the 32-byte public key.
///
/// Returns `Some([u8; 32])` if the DID has the expected format
/// (`did:presidium:<base58-encoded-32-byte-public-key>`) and the
/// Base58 payload decodes to exactly 32 bytes. Returns `None` for any
/// malformed, wrongly prefixed, or incorrectly sized input.
///
/// # Example
///
/// ```ignore
/// use presidium_crypto::identity::parse_did;
/// if let Some(pk_bytes) = parse_did("did:presidium:3Yjsd1N2k8mjLtYk") {
///     println!("Public key: {:?}", pk_bytes);
/// }
/// ```
#[must_use]
pub fn parse_did(did: &str) -> Option<[u8; 32]> {
    let encoded = did.strip_prefix("did:presidium:")?;
    if encoded.is_empty() {
        return None;
    }
    let bytes = bs58::decode(encoded).into_vec().ok()?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn generate_produces_valid_did() {
        let (identity, _mnemonic) = Identity::generate();
        assert!(
            identity.did().starts_with("did:presidium:"),
            "DID must start with did:presidium:"
        );
        assert!(
            identity.did().len() > "did:presidium:".len(),
            "DID must have a non-empty payload"
        );
    }

    #[test]
    fn public_key_is_32_bytes() {
        let (identity, _mnemonic) = Identity::generate();
        assert_eq!(identity.public_key_bytes().len(), 32);
    }

    #[test]
    fn roundtrip_via_mnemonic() {
        let (original, mnemonic) = Identity::generate();
        let recovered = Identity::recover(&mnemonic).expect("valid mnemonic should recover");
        assert_eq!(original.public_key_bytes(), recovered.public_key_bytes());
        assert_eq!(original.did(), recovered.did());
    }

    #[test]
    fn recovered_identity_matches_original_signing_key() {
        let (original, mnemonic) = Identity::generate();
        let recovered = Identity::recover(&mnemonic).expect("valid mnemonic should recover");
        assert_eq!(
            original.signing_key().to_bytes(),
            recovered.signing_key().to_bytes()
        );
    }

    #[test]
    fn reject_12_word_mnemonic() {
        let short: Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .parse()
            .expect("valid 12-word mnemonic");
        assert!(matches!(
            Identity::recover(&short),
            Err(IdentityError::InvalidSeedPhrase(12))
        ));
    }

    #[test]
    fn reject_15_word_mnemonic() {
        // Generate 15-word entropy (20 bytes) — construct manually
        let entropy_20 = [0u8; 20];
        let mnemonic = Mnemonic::from_entropy(&entropy_20).expect("20 bytes → 15-word mnemonic");
        assert_eq!(mnemonic.word_count(), 15);
        assert!(matches!(
            Identity::recover(&mnemonic),
            Err(IdentityError::InvalidSeedPhrase(15))
        ));
    }

    #[test]
    fn parse_valid_did_roundtrip() {
        let (identity, _) = Identity::generate();
        let did_str = identity.did();
        let parsed = parse_did(did_str).expect("valid DID should parse");
        assert_eq!(parsed, identity.public_key_bytes());
    }

    #[test]
    fn parse_invalid_did_returns_none() {
        assert!(parse_did("did:other:abc123").is_none());
        assert!(parse_did("not-a-did").is_none());
        assert!(parse_did("").is_none());
        assert!(parse_did("did:presidium:").is_none());
        assert!(parse_did("did:presidium:!!!invalid-base58!!!").is_none());
    }

    #[test]
    fn different_identities_have_different_keys() {
        let (id1, _) = Identity::generate();
        let (id2, _) = Identity::generate();
        assert_ne!(id1.public_key_bytes(), id2.public_key_bytes());
        assert_ne!(id1.did(), id2.did());
    }

    #[test]
    fn identity_clone_independence() {
        let (original, _) = Identity::generate();
        let clone = original.clone();
        assert_eq!(original.did(), clone.did());
        assert_eq!(original.public_key_bytes(), clone.public_key_bytes());
    }
}
