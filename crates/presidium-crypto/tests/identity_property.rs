#![allow(clippy::unwrap_used, clippy::expect_used)]

use presidium_crypto::identity::{parse_did, Identity};
use proptest::prelude::*;

/// Strategy that generates a random valid 24-word English mnemonic.
///
/// BIP39 maps 32 bytes (256 bits) of entropy to exactly 24 words.
fn mnemonic_strategy() -> impl Strategy<Value = bip39::Mnemonic> {
    any::<[u8; 32]>().prop_map(|entropy| {
        bip39::Mnemonic::from_entropy(&entropy)
            .expect("32 bytes always produce a valid 24-word mnemonic")
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn identity_roundtrip(mnemonic in mnemonic_strategy()) {
        let identity = Identity::recover(&mnemonic)
            .expect("recovery from valid 24-word mnemonic must succeed");
        let recovered = Identity::recover(&mnemonic)
            .expect("second recovery must also succeed");
        assert_eq!(identity.public_key_bytes(), recovered.public_key_bytes());
        assert_eq!(identity.did(), recovered.did());
    }

    #[test]
    fn did_format_valid(mnemonic in mnemonic_strategy()) {
        let identity = Identity::recover(&mnemonic)
            .expect("recovery from valid mnemonic must succeed");
        let did = identity.did();

        // DID must have the correct prefix
        assert!(did.starts_with("did:presidium:"));

        // The Base58 payload must decode to exactly 32 bytes matching the public key
        let encoded = did.strip_prefix("did:presidium:").unwrap();
        let decoded = bs58::decode(encoded).into_vec()
            .expect("DID payload must be valid Base58");
        assert_eq!(decoded.len(), 32, "public key must be 32 bytes");
        assert_eq!(decoded, identity.public_key_bytes().to_vec());
    }

    #[test]
    fn parse_did_roundtrip(mnemonic in mnemonic_strategy()) {
        let identity = Identity::recover(&mnemonic)
            .expect("recovery must succeed");
        let did_str = identity.did();
        let parsed = parse_did(did_str)
            .expect("valid DID must parse");
        assert_eq!(parsed, identity.public_key_bytes());
    }

    #[test]
    fn public_key_consistency(mnemonic in mnemonic_strategy()) {
        let identity = Identity::recover(&mnemonic)
            .expect("recovery must succeed");
        let vk_bytes = identity.verifying_key().to_bytes();
        assert_eq!(vk_bytes, identity.public_key_bytes());
    }
}

#[test]
fn generate_then_recover_deterministic() {
    let (original, mnemonic) = Identity::generate();
    let recovered = Identity::recover(&mnemonic).expect("mnemonic from generate must recover");
    assert_eq!(original.public_key_bytes(), recovered.public_key_bytes());
    assert_eq!(original.did(), recovered.did());
    assert_eq!(
        original.signing_key().to_bytes(),
        recovered.signing_key().to_bytes()
    );
}

#[test]
fn invalid_seed_phrase_12_words() {
    let bad: bip39::Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        .parse()
        .expect("valid 12-word mnemonic");
    assert!(Identity::recover(&bad).is_err());
}

#[test]
fn parse_did_edge_cases() {
    assert!(parse_did("").is_none());
    assert!(parse_did("did:presidium:").is_none());
    assert!(parse_did("did:other:something").is_none());
    assert!(parse_did("did:presidium:\x00\x00").is_none());
    // Very long input should not panic
    let long = format!("did:presidium:{}", "A".repeat(1000));
    let _ = parse_did(&long);
}
