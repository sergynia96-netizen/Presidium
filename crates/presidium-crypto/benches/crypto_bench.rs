#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::semicolon_if_nothing_returned,
    clippy::similar_names
)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ed25519_dalek::SigningKey;
use presidium_crypto::identity::Identity;
use presidium_crypto::ratchet::RatchetState;
use presidium_crypto::vault::{decrypt, encrypt};
use presidium_crypto::x3dh::{
    ed25519_public_to_x25519, initiate, respond, OneTimePreKey, PreKeyBundle, SignedPreKey,
};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

fn bench_identity_generate(c: &mut Criterion) {
    c.bench_function("identity generate", |b| {
        b.iter(|| {
            let (id, _) = Identity::generate();
            black_box(id);
        });
    });
}

fn bench_identity_recover(c: &mut Criterion) {
    let (_, mnemonic) = Identity::generate();
    c.bench_function("identity recover", |b| {
        b.iter(|| {
            let id = Identity::recover(black_box(&mnemonic)).unwrap();
            black_box(id);
        });
    });
}

fn bench_identity_did_parse(c: &mut Criterion) {
    let (identity, _) = Identity::generate();
    let did = identity.did().to_string();
    c.bench_function("identity did parse", |b| {
        b.iter(|| {
            let _ = presidium_crypto::identity::parse_did(black_box(&did));
        });
    });
}

fn bench_vault_encrypt(c: &mut Criterion) {
    let plaintext = b"Some data to encrypt";
    let password = "benchmark password";
    c.bench_function("vault encrypt", |b| {
        b.iter(|| {
            let ct = encrypt(black_box(plaintext), black_box(password)).unwrap();
            black_box(ct);
        });
    });
}

fn bench_vault_decrypt(c: &mut Criterion) {
    let plaintext = b"Some data to encrypt";
    let password = "benchmark password";
    let ct = encrypt(plaintext, password).unwrap();
    c.bench_function("vault decrypt", |b| {
        b.iter(|| {
            let pt = decrypt(black_box(&ct), black_box(password)).unwrap();
            black_box(pt);
        });
    });
}

/// Benchmark: X3DH initiate (Alice's side) with one-time prekey.
fn bench_x3dh_initiate(c: &mut Criterion) {
    let alice_sk = SigningKey::generate(&mut OsRng);
    let bob_sk = SigningKey::generate(&mut OsRng);

    let bob_spk = X25519StaticSecret::random_from_rng(OsRng);
    let bob_spk_pub = X25519PublicKey::from(&bob_spk);
    let bob_opk = X25519StaticSecret::random_from_rng(OsRng);
    let bob_opk_pub = X25519PublicKey::from(&bob_opk);

    let bundle = PreKeyBundle {
        identity_key: ed25519_public_to_x25519(bob_sk.verifying_key()).unwrap(),
        signed_pre_key: SignedPreKey { key: bob_spk_pub },
        one_time_pre_keys: vec![OneTimePreKey { key: bob_opk_pub }],
    };

    // Pre-generate a fresh ephemeral for each iteration (can't reuse after DH)
    c.bench_function("x3dh initiate (with OPK)", |b| {
        b.iter(|| {
            let alice_eph = X25519StaticSecret::random_from_rng(OsRng);
            let (shared, ek_a) = initiate(
                black_box(&alice_sk),
                black_box(&alice_eph),
                black_box(&bundle),
            )
            .unwrap();
            black_box(shared);
            black_box(ek_a);
        });
    });
}

/// Benchmark: X3DH respond (Bob's side) with one-time prekey.
fn bench_x3dh_respond(c: &mut Criterion) {
    let alice_sk = SigningKey::generate(&mut OsRng);
    let bob_sk = SigningKey::generate(&mut OsRng);

    let bob_spk = X25519StaticSecret::random_from_rng(OsRng);
    let bob_opk = X25519StaticSecret::random_from_rng(OsRng);

    // Pre-compute the ephemeral public key Alice sends to Bob
    let alice_eph = X25519StaticSecret::random_from_rng(OsRng);
    let alice_eph_pub = X25519PublicKey::from(&alice_eph);

    c.bench_function("x3dh respond (with OPK)", |b| {
        b.iter(|| {
            let shared = respond(
                black_box(&bob_sk),
                black_box(&bob_spk),
                black_box(Some(&bob_opk)),
                black_box(alice_sk.verifying_key()),
                black_box(&alice_eph_pub),
            )
            .unwrap();
            black_box(shared);
        });
    });
}

/// Benchmark: X3DH initiate without one-time prekey.
fn bench_x3dh_initiate_no_opk(c: &mut Criterion) {
    let alice_sk = SigningKey::generate(&mut OsRng);
    let bob_sk = SigningKey::generate(&mut OsRng);

    let bob_spk = X25519StaticSecret::random_from_rng(OsRng);
    let bob_spk_pub = X25519PublicKey::from(&bob_spk);

    let bundle = PreKeyBundle {
        identity_key: ed25519_public_to_x25519(bob_sk.verifying_key()).unwrap(),
        signed_pre_key: SignedPreKey { key: bob_spk_pub },
        one_time_pre_keys: vec![],
    };

    c.bench_function("x3dh initiate (no OPK)", |b| {
        b.iter(|| {
            let alice_eph = X25519StaticSecret::random_from_rng(OsRng);
            let (shared, ek_a) = initiate(
                black_box(&alice_sk),
                black_box(&alice_eph),
                black_box(&bundle),
            )
            .unwrap();
            black_box(shared);
            black_box(ek_a);
        });
    });
}

/// Benchmark: Ed25519 to X25519 key conversions.
fn bench_ed25519_to_x25519(c: &mut Criterion) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();

    c.bench_function("ed25519 to x25519 secret", |b| {
        b.iter(|| {
            let _ = presidium_crypto::x3dh::ed25519_to_x25519_static(black_box(&sk));
        });
    });

    c.bench_function("ed25519 to x25519 public", |b| {
        b.iter(|| {
            let _ = ed25519_public_to_x25519(black_box(vk)).unwrap();
        });
    });
}

/// Benchmark: Double Ratchet encrypt step.
fn bench_ratchet_encrypt(c: &mut Criterion) {
    let shared = [0u8; 32];
    let a_sec = X25519StaticSecret::random_from_rng(OsRng);
    let b_sec = X25519StaticSecret::random_from_rng(OsRng);
    let b_pub = X25519PublicKey::from(&b_sec);
    let mut state = RatchetState::new(shared, true, a_sec, b_pub);

    // Warm up: first encrypt triggers the initial DH ratchet
    let _ = state.encrypt(b"warmup");

    c.bench_function("ratchet encrypt", |b| {
        b.iter(|| state.encrypt(black_box(b"benchmark message")))
    });
}

/// Benchmark: Double Ratchet decrypt step (after DH ratchet).
fn bench_ratchet_decrypt(c: &mut Criterion) {
    let shared = [0u8; 32];
    let a_sec = X25519StaticSecret::random_from_rng(OsRng);
    let a_pub = X25519PublicKey::from(&a_sec);
    let b_sec = X25519StaticSecret::random_from_rng(OsRng);
    let b_pub = X25519PublicKey::from(&b_sec);

    let mut alice = RatchetState::new(shared, true, a_sec, b_pub);
    let mut bob = RatchetState::new(shared, false, b_sec, a_pub);

    c.bench_function("ratchet decrypt", |b| {
        b.iter(|| {
            // Need a fresh message each time since decrypt advances the chain
            let fresh = alice.encrypt(black_box(b"benchmark message")).unwrap();
            let _ = bob.decrypt(&fresh).unwrap();
        });
    });
}

/// Benchmark: Double Ratchet full DH ratchet + encrypt.
fn bench_ratchet_dh_step(c: &mut Criterion) {
    c.bench_function("ratchet dh ratchet + encrypt", |b| {
        b.iter(|| {
            let shared = [0u8; 32];
            let a_sec = X25519StaticSecret::random_from_rng(OsRng);
            let a_pub = X25519PublicKey::from(&a_sec);
            let b_sec = X25519StaticSecret::random_from_rng(OsRng);
            let b_pub = X25519PublicKey::from(&b_sec);
            let mut alice = RatchetState::new(shared, true, a_sec, b_pub);
            let mut bob = RatchetState::new(shared, false, b_sec, a_pub);

            let enc = alice.encrypt(black_box(b"test")).unwrap();
            let dec = bob.decrypt(&enc).unwrap();
            black_box(dec);
        });
    });
}

criterion_group!(
    benches,
    bench_identity_generate,
    bench_identity_recover,
    bench_identity_did_parse,
    bench_vault_encrypt,
    bench_vault_decrypt,
    bench_x3dh_initiate,
    bench_x3dh_respond,
    bench_x3dh_initiate_no_opk,
    bench_ed25519_to_x25519,
    bench_ratchet_encrypt,
    bench_ratchet_decrypt,
    bench_ratchet_dh_step
);
criterion_main!(benches);
