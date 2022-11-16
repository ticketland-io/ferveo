use criterion::{black_box, criterion_group, criterion_main, Criterion};

pub fn bench_encrypt_combine(c: &mut Criterion) {
    fn encrypt_bench(
        num_shares: usize,
        num_entities: usize,
        threshold: usize,
    ) -> impl Fn() {
        let message = "my-secret-message".as_bytes().to_vec();
        let setup = tpke_wasm::Setup::new(threshold, num_shares, num_entities);
        move || {
            let message = message.clone();
            black_box(tpke_wasm::encrypt(message, setup.public_key));
        }
    }

    let mut group = c.benchmark_group("TPKE-WASM");
    group.sample_size(10);

    for num_shares in [8, 16, 32, 64, 128].iter() {
        let a = encrypt_bench(*num_shares, *num_shares, *num_shares);
        group.measurement_time(core::time::Duration::new(30, 0));
        group.bench_function(format!("tpke-wasm::encrypt - num_shares={}, num_entities={}, threshold={}", num_shares, num_shares, num_shares), |b| {
                b.iter(|| a())
            });
    }
}

criterion_group!(benches, bench_encrypt_combine);
criterion_main!(benches);
