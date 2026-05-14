//! Identity management: Ed25519 signing key, DID, BIP39 seed phrase.

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
    /// Key derivation from the BIP39 seed failed.
    #[error("failed to derive keypair from seed")]
    KeyDerivationFailed,
}

/// A Presidium identity: Ed25519 signing key + DID.
///
/// Holds the long-term Ed25519 keypair used for signing and authentication,
/// along with the corresponding Decentralized Identifier (DID).
///
/// # Security
///
/// The underlying [`SigningKey`] from `ed25519-dalek` implements `ZeroizeOnDrop`,
/// ensuring secret bytes are overwritten when the `Identity` is dropped.
#[derive(Clone)]
pub struct Identity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    did: String,
}

impl Identity {
    /// Generate a new random identity, returning the identity and a 24-word BIP39 mnemonic.
    ///
    /// Uses [`OsRng`] exclusively for entropy — no `thread_rng` or predictable sources.
    /// The mnemonic can be used to recover the identity later via [`Identity::recover`].
    ///
    /// # Panics
    ///
    /// Will never panic: 32-byte entropy is guaranteed valid by BIP39 for 24-word
    /// mnemonics, and `SigningKey::from_bytes` is infallible for any 32-byte input.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (identity, mnemonic) = Identity::generate();
    /// println!("DID: {}", identity.did());
    /// println!("Seed: {}", mnemonic.to_phrase());
    /// ```
    #[must_use]
    pub fn generate() -> (Self, Mnemonic) {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        // SAFETY: 32 bytes of entropy always maps to a valid 24-word mnemonic per BIP39.
        let Ok(mnemonic) = Mnemonic::from_entropy(&entropy) else {
            unreachable!("32-byte entropy is always valid for a 24-word mnemonic")
        };
        let identity = Self::from_mnemonic_internal(&mnemonic);
        (identity, mnemonic)
    }

    /// Recover an identity from a BIP39 mnemonic (must be exactly 24 words).
    ///
    /// Derives the Ed25519 signing key from the first 32 bytes of the BIP39 seed
    /// and reconstructs the DID from the verifying key.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidSeedPhrase`] if the mnemonic does not
    /// contain exactly 24 words.
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

    /// Internal: derive identity from a validated mnemonic.
    ///
    /// The caller guarantees that the mnemonic has exactly 24 words.
    fn from_mnemonic_internal(mnemonic: &Mnemonic) -> Self {
        let seed = mnemonic.to_seed("");
        // BIP39 seed is always exactly 64 bytes. Copy the first 32 into a fixed-size array.
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&seed[..SECRET_KEY_LENGTH]);
        let signing_key = SigningKey::from_bytes(&sk_bytes);
        let verifying_key = signing_key.verifying_key();
        let did = did_from_verifying_key(&verifying_key);
        Self {
            signing_key,
            verifying_key,
            did,
        }
    }
}

/// Parse a DID string and extract the 32-byte public key.
///
/// Returns `Some([u8; 32])` if the DID has the expected format and contains
/// valid Base58-encoded 32 bytes. Returns `None` otherwise.
///
/// # Format
///
/// ```text
/// did:presidium:<base58-encoded-32-byte-public-key>
/// ```
#[must_use]
pub fn parse_did(did: &str) -> Option<[u8; 32]> {
    let encoded = did.strip_prefix("did:presidium:")?;
    let bytes = bs58::decode(encoded).into_vec().ok()?;
    bytes.try_into().ok()
}

/// Build a DID from an Ed25519 verifying (public) key.
fn did_from_verifying_key(vk: &VerifyingKey) -> String {
    format!(
        "did:presidium:{}",
        bs58::encode(vk.to_bytes()).into_string()
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn generate_produces_valid_did() {
        let (identity, _mnemonic) = Identity::generate();
        assert!(identity.did().starts_with("did:presidium:"));
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
    fn parse_valid_did() {
        let (identity, _) = Identity::generate();
        let parsed = parse_did(identity.did()).expect("valid DID should parse");
        assert_eq!(parsed, identity.public_key_bytes());
    }

    #[test]
    fn parse_invalid_did_returns_none() {
        assert!(parse_did("did:other:abc").is_none());
        assert!(parse_did("not-a-did").is_none());
        assert!(parse_did("did:presidium:").is_none());
        assert!(parse_did("did:presidium:!!!invalid-base58!!!").is_none());
    }
}
