#![allow(clippy::unwrap_used, clippy::expect_used)]

use presidium_crypto::ratchet::RatchetState;
use proptest::prelude::*;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

fn init_pair() -> (RatchetState, RatchetState) {
    let shared = [42u8; 32];
    let a_sec = X25519StaticSecret::random_from_rng(OsRng);
    let a_pub = X25519PublicKey::from(&a_sec);
    let b_sec = X25519StaticSecret::random_from_rng(OsRng);
    let b_pub = X25519PublicKey::from(&b_sec);
    let alice = RatchetState::new(shared, true, a_sec, b_pub);
    let bob = RatchetState::new(shared, false, b_sec, a_pub);
    (alice, bob)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn ratchet_roundtrip_n_messages(n in 1..20usize) {
        let (mut alice, mut bob) = init_pair();
        for i in 0..n {
            let msg = format!("msg{i}");
            let ct = alice.encrypt(msg.as_bytes()).unwrap();
            let pt = bob.decrypt(&ct).unwrap();
            prop_assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn interleaved_property(msgs_alice in prop::collection::vec(".*", 1..5), msgs_bob in prop::collection::vec(".*", 1..5)) {
        let (mut alice, mut bob) = init_pair();
        for (a_msg, b_msg) in msgs_alice.iter().zip(msgs_bob.iter()) {
            let enc_a = alice.encrypt(a_msg.as_bytes()).unwrap();
            let dec_a = bob.decrypt(&enc_a).unwrap();
            prop_assert_eq!(dec_a, a_msg.as_bytes());

            let enc_b = bob.encrypt(b_msg.as_bytes()).unwrap();
            let dec_b = alice.decrypt(&enc_b).unwrap();
            prop_assert_eq!(dec_b, b_msg.as_bytes());
        }
    }

    #[test]
    fn bob_alice_alternating_long(n in 1..10usize) {
        let (mut alice, mut bob) = init_pair();
        for i in 0..n {
            let msg_a = format!("alice-{i}");
            let enc_a = alice.encrypt(msg_a.as_bytes()).unwrap();
            let dec_a = bob.decrypt(&enc_a).unwrap();
            prop_assert_eq!(dec_a, msg_a.as_bytes());

            let msg_b = format!("bob-{i}");
            let enc_b = bob.encrypt(msg_b.as_bytes()).unwrap();
            let dec_b = alice.decrypt(&enc_b).unwrap();
            prop_assert_eq!(dec_b, msg_b.as_bytes());
        }
    }
}
