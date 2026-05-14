#![allow(clippy::unwrap_used, clippy::expect_used, clippy::similar_names)]

use ed25519_dalek::SigningKey;
use presidium_crypto::x3dh::{
    ed25519_public_to_x25519, initiate, respond, OneTimePreKey, PreKeyBundle, SignedPreKey,
};
use proptest::prelude::*;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn handshake_with_opk_always_matches(
        alice_seed in any::<[u8; 32]>(),
        bob_seed in any::<[u8; 32]>(),
        spk_seed in any::<[u8; 32]>(),
        opk_seed in any::<[u8; 32]>(),
        eph_seed in any::<[u8; 32]>(),
    ) {
        let alice_sk = SigningKey::from_bytes(&alice_seed);
        let bob_sk = SigningKey::from_bytes(&bob_seed);
        let bob_spk = X25519StaticSecret::from(spk_seed);
        let bob_spk_pub = X25519PublicKey::from(&bob_spk);
        let bob_opk = X25519StaticSecret::from(opk_seed);
        let bob_opk_pub = X25519PublicKey::from(&bob_opk);
        let alice_eph = X25519StaticSecret::from(eph_seed);

        let bundle = PreKeyBundle {
            identity_key: ed25519_public_to_x25519(bob_sk.verifying_key()).unwrap(),
            signed_pre_key: SignedPreKey { key: bob_spk_pub },
            one_time_pre_keys: vec![OneTimePreKey { key: bob_opk_pub }],
        };

        let (alice_shared, ek_a) = initiate(&alice_sk, &alice_eph, &bundle).unwrap();

        let bob_shared = respond(
            &bob_sk,
            &bob_spk,
            Some(&bob_opk),
            alice_sk.verifying_key(),
            &ek_a,
        ).unwrap();

        prop_assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn handshake_without_opk_always_matches(
        alice_seed in any::<[u8; 32]>(),
        bob_seed in any::<[u8; 32]>(),
        spk_seed in any::<[u8; 32]>(),
        eph_seed in any::<[u8; 32]>(),
    ) {
        let alice_sk = SigningKey::from_bytes(&alice_seed);
        let bob_sk = SigningKey::from_bytes(&bob_seed);
        let bob_spk = X25519StaticSecret::from(spk_seed);
        let bob_spk_pub = X25519PublicKey::from(&bob_spk);
        let alice_eph = X25519StaticSecret::from(eph_seed);

        let bundle = PreKeyBundle {
            identity_key: ed25519_public_to_x25519(bob_sk.verifying_key()).unwrap(),
            signed_pre_key: SignedPreKey { key: bob_spk_pub },
            one_time_pre_keys: vec![],
        };

        let (alice_shared, ek_a) = initiate(&alice_sk, &alice_eph, &bundle).unwrap();

        let bob_shared = respond(
            &bob_sk,
            &bob_spk,
            None,
            alice_sk.verifying_key(),
            &ek_a,
        ).unwrap();

        prop_assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn shared_secret_depends_on_identity_keys(
        alice_seed_a in any::<[u8; 32]>(),
        alice_seed_b in any::<[u8; 32]>(),
        bob_seed in any::<[u8; 32]>(),
        spk_seed in any::<[u8; 32]>(),
        opk_seed in any::<[u8; 32]>(),
    ) {
        // Skip if the two Alice seeds happen to be the same
        prop_assume!(alice_seed_a != alice_seed_b);

        let alice_sk_a = SigningKey::from_bytes(&alice_seed_a);
        let alice_sk_b = SigningKey::from_bytes(&alice_seed_b);
        let bob_sk = SigningKey::from_bytes(&bob_seed);
        let bob_spk = X25519StaticSecret::from(spk_seed);
        let bob_spk_pub = X25519PublicKey::from(&bob_spk);
        let bob_opk = X25519StaticSecret::from(opk_seed);
        let bob_opk_pub = X25519PublicKey::from(&bob_opk);

        let bundle = PreKeyBundle {
            identity_key: ed25519_public_to_x25519(bob_sk.verifying_key()).unwrap(),
            signed_pre_key: SignedPreKey { key: bob_spk_pub },
            one_time_pre_keys: vec![OneTimePreKey { key: bob_opk_pub }],
        };

        let eph_a = X25519StaticSecret::random_from_rng(OsRng);
        let eph_b = X25519StaticSecret::random_from_rng(OsRng);

        let (secret_a, _) = initiate(&alice_sk_a, &eph_a, &bundle).unwrap();
        let (secret_b, _) = initiate(&alice_sk_b, &eph_b, &bundle).unwrap();

        prop_assert_ne!(secret_a, secret_b);
    }

    #[test]
    fn shared_secret_depends_on_ephemeral_key(
        alice_seed in any::<[u8; 32]>(),
        bob_seed in any::<[u8; 32]>(),
        spk_seed in any::<[u8; 32]>(),
        opk_seed in any::<[u8; 32]>(),
        eph_seed_a in any::<[u8; 32]>(),
        eph_seed_b in any::<[u8; 32]>(),
    ) {
        // Skip if the two ephemeral seeds happen to be the same
        prop_assume!(eph_seed_a != eph_seed_b);

        let alice_sk = SigningKey::from_bytes(&alice_seed);
        let bob_sk = SigningKey::from_bytes(&bob_seed);
        let bob_spk = X25519StaticSecret::from(spk_seed);
        let bob_spk_pub = X25519PublicKey::from(&bob_spk);
        let bob_opk = X25519StaticSecret::from(opk_seed);
        let bob_opk_pub = X25519PublicKey::from(&bob_opk);

        let bundle = PreKeyBundle {
            identity_key: ed25519_public_to_x25519(bob_sk.verifying_key()).unwrap(),
            signed_pre_key: SignedPreKey { key: bob_spk_pub },
            one_time_pre_keys: vec![OneTimePreKey { key: bob_opk_pub }],
        };

        let eph_a = X25519StaticSecret::from(eph_seed_a);
        let eph_b = X25519StaticSecret::from(eph_seed_b);

        let (secret_a, _) = initiate(&alice_sk, &eph_a, &bundle).unwrap();
        let (secret_b, _) = initiate(&alice_sk, &eph_b, &bundle).unwrap();

        prop_assert_ne!(secret_a, secret_b);
    }

    #[test]
    fn public_key_conversion_is_deterministic(seed in any::<[u8; 32]>()) {
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();

        let x1 = ed25519_public_to_x25519(vk).unwrap();
        let x2 = ed25519_public_to_x25519(vk).unwrap();

        prop_assert_eq!(x1.as_bytes(), x2.as_bytes());
    }

    #[test]
    fn public_key_conversion_matches_secret_derivation(seed in any::<[u8; 32]>()) {
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();

        let x_pub = ed25519_public_to_x25519(vk).unwrap();
        let x_secret = presidium_crypto::x3dh::ed25519_to_x25519_static(&sk);
        let x_pub_from_secret = X25519PublicKey::from(&x_secret);

        // The DH output of (derived_secret, public_from_conversion) should match
        // the DH output of (derived_secret, public_from_secret)
        let dh1 = x_secret.diffie_hellman(&x_pub);
        let dh2 = x_secret.diffie_hellman(&x_pub_from_secret);

        prop_assert_eq!(dh1.as_bytes(), dh2.as_bytes());
    }
}

#[test]
fn opk_mismatch_produces_different_secret() {
    let alice_sk = SigningKey::generate(&mut OsRng);
    let bob_sk = SigningKey::generate(&mut OsRng);

    let bob_spk = X25519StaticSecret::random_from_rng(OsRng);
    let bob_spk_pub = X25519PublicKey::from(&bob_spk);
    let _ = bob_spk; // used only for public key generation

    let bob_opk_used = X25519StaticSecret::random_from_rng(OsRng);
    let bob_opk_used_pub = X25519PublicKey::from(&bob_opk_used);

    let bob_opk_other = X25519StaticSecret::random_from_rng(OsRng);

    let bundle = PreKeyBundle {
        identity_key: ed25519_public_to_x25519(bob_sk.verifying_key()).unwrap(),
        signed_pre_key: SignedPreKey { key: bob_spk_pub },
        one_time_pre_keys: vec![OneTimePreKey {
            key: bob_opk_used_pub,
        }],
    };

    let alice_eph = X25519StaticSecret::random_from_rng(OsRng);
    let (alice_shared, ek_a) = initiate(&alice_sk, &alice_eph, &bundle).unwrap();

    // Bob responds with the correct OPK
    let bob_shared_correct = respond(
        &bob_sk,
        &bob_spk,
        Some(&bob_opk_used),
        alice_sk.verifying_key(),
        &ek_a,
    )
    .unwrap();
    assert_eq!(alice_shared, bob_shared_correct);

    // Bob responds with the wrong OPK — secrets must differ
    let bob_shared_wrong = respond(
        &bob_sk,
        &bob_spk,
        Some(&bob_opk_other),
        alice_sk.verifying_key(),
        &ek_a,
    )
    .unwrap();
    assert_ne!(alice_shared, bob_shared_wrong);
}

#[test]
fn opk_vs_no_opk_produces_different_secret() {
    let alice_sk = SigningKey::generate(&mut OsRng);
    let bob_sk = SigningKey::generate(&mut OsRng);

    let bob_spk = X25519StaticSecret::random_from_rng(OsRng);
    let bob_spk_pub = X25519PublicKey::from(&bob_spk);
    let bob_opk = X25519StaticSecret::random_from_rng(OsRng);
    let bob_opk_pub = X25519PublicKey::from(&bob_opk);
    let _ = bob_spk;
    let _ = bob_opk;

    // Bundle with OPK
    let bundle_with_opk = PreKeyBundle {
        identity_key: ed25519_public_to_x25519(bob_sk.verifying_key()).unwrap(),
        signed_pre_key: SignedPreKey { key: bob_spk_pub },
        one_time_pre_keys: vec![OneTimePreKey { key: bob_opk_pub }],
    };

    // Bundle without OPK
    let bundle_no_opk = PreKeyBundle {
        identity_key: ed25519_public_to_x25519(bob_sk.verifying_key()).unwrap(),
        signed_pre_key: SignedPreKey { key: bob_spk_pub },
        one_time_pre_keys: vec![],
    };

    // Use the same ephemeral key for both to prove the OPK changes the secret
    let eph_seed = [42u8; 32];
    let alice_eph = X25519StaticSecret::from(eph_seed);

    let (secret_with_opk, _) = initiate(&alice_sk, &alice_eph, &bundle_with_opk).unwrap();
    // Same ephemeral key again (deterministic from same seed)
    let alice_eph2 = X25519StaticSecret::from(eph_seed);
    let (secret_no_opk, _) = initiate(&alice_sk, &alice_eph2, &bundle_no_opk).unwrap();

    assert_ne!(
        secret_with_opk, secret_no_opk,
        "OPK must change the shared secret even with the same ephemeral key"
    );
}
