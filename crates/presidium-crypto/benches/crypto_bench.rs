#![allow(clippy::expect_used, clippy::unwrap_used)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use presidium_crypto::identity::Identity;

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
            let id = Identity::recover(black_box(&mnemonic)).expect("valid mnemonic");
            black_box(id);
        });
    });
}

criterion_group!(benches, bench_identity_generate, bench_identity_recover);
criterion_main!(benches);
