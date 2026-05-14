//! Vault: password-based encryption for sensitive user data.
//!
//! Uses Argon2id (memory-hard KDF) to derive a 256-bit key from a password,
//! then encrypts with `ChaCha20Poly1305` (AEAD). The wire format is:
//!
//! ```text
//! salt (16 B) || nonce (12 B) || ciphertext+tag (variable)
//! ```
//!
//! # Security
//!
//! - Argon2id with 64 MiB memory, 3 iterations, 4 parallel lanes — tuned to
//!   resist GPU/ASIC attacks while remaining usable on mobile devices.
//! - Each encryption call generates a fresh random salt and nonce.
//! - The derived key is zeroized after use via the [`zeroize::Zeroize`] trait.
//! - `ChaCha20Poly1305` provides authenticated encryption: any tampering with
//!   the ciphertext is detected during decryption.
//!
//! # Example
//!
//! ```ignore
//! use presidium_crypto::vault::{encrypt, decrypt};
//!
//! let secret = b"my identity private key bytes";
//! let ct = encrypt(secret, "strong_passphrase")?;
//! let pt = decrypt(&ct, "strong_passphrase")?;
//! assert_eq!(pt, secret);
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::Rng;
use thiserror::Error;
use zeroize::Zeroize;

/// Errors that can occur during vault operations.
#[derive(Error, Debug)]
pub enum VaultError {
    /// Encryption failed (key derivation or AEAD encryption error).
    #[error("encryption failed")]
    EncryptionFailed,
    /// Decryption failed (input too short or corrupted format).
    #[error("decryption failed: invalid ciphertext format")]
    DecryptionFailed,
    /// The password is wrong or the ciphertext has been tampered with.
    #[error("invalid password or corrupted data")]
    InvalidPassword,
}

/// Argon2id memory cost in kibibytes (64 MiB).
const ARGON2_M_COST: u32 = 64 * 1024;
/// Argon2id time cost (number of iterations).
const ARGON2_T_COST: u32 = 3;
/// Argon2id parallelism (number of lanes).
const ARGON2_P_COST: u32 = 4;

/// Salt length in bytes (128 bits).
const SALT_LENGTH: usize = 16;
/// Nonce length in bytes (96 bits, as required by `ChaCha20Poly1305`).
const NONCE_LENGTH: usize = 12;

/// Encrypt `plaintext` with `password`.
///
/// Derives a 256-bit key from the password using Argon2id (with a fresh random
/// salt), then encrypts the plaintext with `ChaCha20Poly1305` (fresh random nonce).
///
/// Returns the concatenation: `salt (16 B) || nonce (12 B) || ciphertext+tag`.
///
/// # Errors
///
/// Returns [`VaultError::EncryptionFailed`] if key derivation or AEAD encryption fails.
pub fn encrypt(plaintext: &[u8], password: &str) -> Result<Vec<u8>, VaultError> {
    let mut rng = rand::rngs::OsRng;
    let salt: [u8; SALT_LENGTH] = rng.gen();
    let nonce_bytes: [u8; NONCE_LENGTH] = rng.gen();

    let mut key = derive_key(password, &salt)?;

    let cipher =
        ChaCha20Poly1305::new_from_slice(&key).map_err(|_| VaultError::EncryptionFailed)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| VaultError::EncryptionFailed)?;

    // Assemble: salt || nonce || ciphertext
    let mut output = Vec::with_capacity(SALT_LENGTH + NONCE_LENGTH + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    // Wipe the derived key from memory
    key.zeroize();

    Ok(output)
}

/// Decrypt `ciphertext` (produced by [`encrypt`]) with `password`.
///
/// Extracts the salt and nonce from the ciphertext header, re-derives the key,
/// and attempts AEAD decryption. Returns the original plaintext on success.
///
/// # Errors
///
/// - [`VaultError::DecryptionFailed`] if the ciphertext is too short to contain
///   the salt and nonce headers.
/// - [`VaultError::InvalidPassword`] if the password is wrong or the ciphertext
///   has been tampered with (AEAD authentication tag mismatch).
pub fn decrypt(ciphertext: &[u8], password: &str) -> Result<Vec<u8>, VaultError> {
    let header_size = SALT_LENGTH + NONCE_LENGTH;
    if ciphertext.len() < header_size {
        return Err(VaultError::DecryptionFailed);
    }

    let (salt, rest) = ciphertext.split_at(SALT_LENGTH);
    let (nonce_bytes, encrypted) = rest.split_at(NONCE_LENGTH);

    let salt_array: [u8; SALT_LENGTH] =
        salt.try_into().map_err(|_| VaultError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let mut key = derive_key(password, &salt_array)?;

    let cipher =
        ChaCha20Poly1305::new_from_slice(&key).map_err(|_| VaultError::DecryptionFailed)?;

    let plaintext = cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| VaultError::InvalidPassword)?;

    // Wipe the derived key from memory
    key.zeroize();

    Ok(plaintext)
}

/// Derive a 256-bit AEAD key from a password and salt using Argon2id.
///
/// Uses the OWASP-recommended parameters for memory-hard key derivation:
/// 64 MiB memory, 3 iterations, 4 parallel lanes.
fn derive_key(password: &str, salt: &[u8; SALT_LENGTH]) -> Result<[u8; 32], VaultError> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|_| VaultError::EncryptionFailed)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output_key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output_key)
        .map_err(|_| VaultError::EncryptionFailed)?;
    Ok(output_key)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"Hello, Presidium!";
        let password = "correct horse battery staple";
        let ciphertext = encrypt(plaintext, password).unwrap();
        let decrypted = decrypt(&ciphertext, password).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_password_fails() {
        let plaintext = b"Secret message";
        let password = "correct";
        let ciphertext = encrypt(plaintext, password).unwrap();
        assert!(matches!(
            decrypt(&ciphertext, "wrong"),
            Err(VaultError::InvalidPassword)
        ));
    }

    #[test]
    fn corrupted_salt_fails() {
        let plaintext = b"Data";
        let password = "pwd";
        let mut ciphertext = encrypt(plaintext, password).unwrap();
        // Corrupt the salt byte (first byte of ciphertext)
        ciphertext[0] ^= 0xff;
        assert!(decrypt(&ciphertext, password).is_err());
    }

    #[test]
    fn corrupted_nonce_fails() {
        let plaintext = b"Data";
        let password = "pwd";
        let mut ciphertext = encrypt(plaintext, password).unwrap();
        // Corrupt a nonce byte (byte 17)
        ciphertext[SALT_LENGTH] ^= 0xff;
        assert!(decrypt(&ciphertext, password).is_err());
    }

    #[test]
    fn corrupted_ciphertext_fails() {
        let plaintext = b"Data";
        let password = "pwd";
        let mut ciphertext = encrypt(plaintext, password).unwrap();
        // Corrupt last byte of ciphertext
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xff;
        assert!(decrypt(&ciphertext, password).is_err());
    }

    #[test]
    fn empty_plaintext() {
        let password = "empty";
        let ct = encrypt(b"", password).unwrap();
        let pt = decrypt(&ct, password).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn ciphertext_format() {
        let plaintext = b"test";
        let ct = encrypt(plaintext, "pw").unwrap();
        // Minimum: 16 (salt) + 12 (nonce) + plaintext (4) + 16 (tag) = 48
        assert_eq!(ct.len(), SALT_LENGTH + NONCE_LENGTH + plaintext.len() + 16);
    }

    #[test]
    fn ciphertext_too_short() {
        // 16 bytes salt + 12 bytes nonce = 28 bytes minimum, we provide less
        let short = vec![0u8; 20];
        assert!(matches!(
            decrypt(&short, "password"),
            Err(VaultError::DecryptionFailed)
        ));
    }

    #[test]
    fn large_plaintext() {
        // 1 KiB of data
        let plaintext = vec![0xAB_u8; 1024];
        let password = "large_data_password";
        let ct = encrypt(&plaintext, password).unwrap();
        let pt = decrypt(&ct, password).unwrap();
        assert_eq!(pt.len(), 1024);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn different_encryptions_produce_different_ciphertexts() {
        let plaintext = b"same data";
        let password = "same password";
        let ct1 = encrypt(plaintext, password).unwrap();
        let ct2 = encrypt(plaintext, password).unwrap();
        // Different random salt/nonce each time → different ciphertexts
        assert_ne!(ct1, ct2);
        // But both decrypt to the same plaintext
        assert_eq!(decrypt(&ct1, password).unwrap(), plaintext);
        assert_eq!(decrypt(&ct2, password).unwrap(), plaintext);
    }

    #[test]
    fn unicode_password() {
        let plaintext = b"unicode test";
        let password = "пароль-кириллица-ß-€-中文";
        let ct = encrypt(plaintext, password).unwrap();
        let pt = decrypt(&ct, password).unwrap();
        assert_eq!(pt, plaintext);
        // Wrong password with similar-looking chars still fails
        assert!(decrypt(&ct, "пароль-кириллица-ß-€-文").is_err());
    }

    #[test]
    fn empty_password() {
        let plaintext = b"empty password test";
        let ct = encrypt(plaintext, "").unwrap();
        let pt = decrypt(&ct, "").unwrap();
        assert_eq!(pt, plaintext);
    }
}
