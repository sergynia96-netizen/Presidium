#![allow(clippy::expect_used, clippy::unwrap_used)]

use bip39::Mnemonic;
use presidium_crypto::identity::{parse_did, Identity};
use proptest::prelude::*;

/// Strategy that generates a random valid 24-word English mnemonic via entropy.
fn mnemonic_strategy() -> impl Strategy<Value = Mnemonic> {
    any::<[u8; 32]>().prop_map(|entropy| {
        Mnemonic::from_entropy(&entropy)
            .expect("32-byte entropy is always valid for a 24-word mnemonic")
    })
}

proptest! {
    /// Recovering from the same mnemonic always produces the same identity.
    #[test]
    fn identity_roundtrip(mnemonic in mnemonic_strategy()) {
        let identity = Identity::recover(&mnemonic)
            .expect("recovery from valid 24-word mnemonic must succeed");
        let recovered = Identity::recover(&mnemonic)
            .expect("second recovery must also succeed");
        assert_eq!(identity.public_key_bytes(), recovered.public_key_bytes());
        assert_eq!(identity.did(), recovered.did());
    }

    /// DID format: starts with "did:presidium:", base58 decodes to 32 bytes matching the public key.
    #[test]
    fn did_format(mnemonic in mnemonic_strategy()) {
        let identity = Identity::recover(&mnemonic).expect("valid mnemonic");
        let did = identity.did();
        assert!(did.starts_with("did:presidium:"));

        let encoded_key = did.strip_prefix("did:presidium:").expect("prefix verified above");
        let decoded = bs58::decode(encoded_key).into_vec().expect("valid base58");
        let decoded_arr: [u8; 32] = decoded.try_into().expect("exactly 32 bytes");
        assert_eq!(decoded_arr, identity.public_key_bytes());
    }

    /// parse_did roundtrip: parsing a generated DID yields the same public key bytes.
    #[test]
    fn parse_did_roundtrip(mnemonic in mnemonic_strategy()) {
        let identity = Identity::recover(&mnemonic).expect("valid mnemonic");
        let did = identity.did();
        let parsed = parse_did(did).expect("valid DID should parse");
        assert_eq!(parsed, identity.public_key_bytes());
    }
}

/// Integration test: generate then recover using `OsRng`.
#[test]
fn generate_then_recover() {
    let (original, mnemonic) = Identity::generate();
    let recovered = Identity::recover(&mnemonic).expect("mnemonic from generate must recover");
    assert_eq!(original.public_key_bytes(), recovered.public_key_bytes());
    assert_eq!(original.did(), recovered.did());
}

/// 12-word mnemonics must be rejected.
#[test]
fn invalid_seed_phrase_12_words() {
    let bad_mnemonic: Mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .parse()
            .expect("valid 12-word mnemonic");
    assert!(Identity::recover(&bad_mnemonic).is_err());
}

/// Invalid DID strings must return `None` from `parse_did`.
#[test]
fn parse_did_rejects_garbage() {
    assert!(parse_did("").is_none());
    assert!(parse_did("did:other:abc123").is_none());
    assert!(parse_did("did:presidium:").is_none());
    assert!(parse_did("did:presidium:!!!not-base58!!!").is_none());
}
