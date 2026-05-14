#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::semicolon_if_nothing_returned
)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use presidium_crypto::identity::Identity;
use presidium_crypto::vault::{decrypt, encrypt};

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

criterion_group!(
    benches,
    bench_identity_generate,
    bench_identity_recover,
    bench_identity_did_parse,
    bench_vault_encrypt,
    bench_vault_decrypt
);
criterion_main!(benches);
