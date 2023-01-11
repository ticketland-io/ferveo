use criterion::{black_box, criterion_group, Criterion};
use rand::Rng;

use ark_ec::ProjectiveCurve;
use ark_ff::UniformRand;

type G1Projective = ark_ec::bls12::G1Projective<ark_bls12_381::Parameters>;

#[macro_export]
macro_rules! mul {
    ($name:ident, $f:ident, $f_type:ty) => {
        pub fn $name() -> impl Fn() {
            const SAMPLES: usize = 1000;

            let mut rng = ark_std::test_rng();

            let v: Vec<_> = (0..SAMPLES)
                .map(|_| ($f::rand(&mut rng), rng.gen::<[u64; 16]>()))
                .collect();

            move || {
                black_box({
                    for (a, b) in &v {
                        let _ = a.mul(&b);
                    }
                })
            }
        }
    };
}

mul!(mul_g1_projective, G1Projective, c);

pub fn bench_mul(c: &mut Criterion) {
    let mut group = c.benchmark_group("mul");
    group.sample_size(10);

    #[allow(clippy::redundant_closure)]
    group.bench_function("G1Projective", |b| b.iter(|| mul_g1_projective()));
}

criterion_group!(benches, bench_mul);
