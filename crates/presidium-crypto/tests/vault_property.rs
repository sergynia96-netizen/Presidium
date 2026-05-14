#![allow(clippy::unwrap_used, clippy::expect_used)]

use presidium_crypto::vault::{decrypt, encrypt};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3))]

    #[test]
    fn roundtrip_no_corruption(
        plaintext in proptest::collection::vec(any::<u8>(), 0..256),
        password in "[ -~]{4,32}",
    ) {
        let ct = encrypt(&plaintext, &password)
            .expect("encryption should succeed for any input");
        let pt = decrypt(&ct, &password)
            .expect("decryption should succeed with correct password");
        prop_assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_password_detected(
        plaintext in proptest::collection::vec(any::<u8>(), 0..64),
        correct in "[ -~]{4,32}",
        wrong in "[ -~]{4,32}",
    ) {
        // Skip if passwords are identical — no point testing
        if correct == wrong {
            return Ok(());
        }
        let ct = encrypt(&plaintext, &correct)
            .expect("encryption should succeed");
        let res = decrypt(&ct, &wrong);
        // Wrong password must always be detected (AEAD authentication)
        prop_assert!(res.is_err());
    }

    #[test]
    fn different_encryptions_differ(
        plaintext in proptest::collection::vec(any::<u8>(), 1..32),
        password in "[ -~]{4,16}",
    ) {
        let ct1 = encrypt(&plaintext, &password).expect("encryption");
        let ct2 = encrypt(&plaintext, &password).expect("encryption");
        // Each call uses fresh salt+nonce, so ciphertexts must differ
        prop_assert_ne!(ct1, ct2);
    }

    #[test]
    fn ciphertext_format_valid(
        plaintext in proptest::collection::vec(any::<u8>(), 0..64),
        password in "[ -~]{4,16}",
    ) {
        let ct = encrypt(&plaintext, &password).expect("encryption");
        // Minimum size: salt (16) + nonce (12) + tag (16) = 44 bytes
        // Even with empty plaintext, ciphertext must be >= 44 bytes
        prop_assert!(ct.len() >= 44);
        prop_assert_eq!(ct.len(), 16 + 12 + plaintext.len() + 16);
    }
}

#[test]
fn empty_plaintext_roundtrip() {
    let password = "empty_test";
    let ct = encrypt(b"", password).unwrap();
    let pt = decrypt(&ct, password).unwrap();
    assert!(pt.is_empty());
}

#[test]
fn short_ciphertext_rejected() {
    // Only 16 bytes — not even enough for salt + nonce
    assert!(decrypt(&[0u8; 16], "password").is_err());
    // 27 bytes — salt + nonce = 28, so 27 is still too short
    assert!(decrypt(&[0u8; 27], "password").is_err());
}

#[test]
fn single_byte_plaintext() {
    let ct = encrypt(b"X", "pw").unwrap();
    let pt = decrypt(&ct, "pw").unwrap();
    assert_eq!(pt, b"X");
}
