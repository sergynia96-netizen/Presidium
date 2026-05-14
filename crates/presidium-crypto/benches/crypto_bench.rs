use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_dummy(c: &mut Criterion) {
    c.bench_function("dummy", |b| b.iter(|| black_box(42)));
}

criterion_group!(benches, bench_dummy);
criterion_main!(benches);
