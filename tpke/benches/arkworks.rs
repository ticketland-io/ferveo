#![allow(clippy::redundant_closure)]
#![allow(clippy::unit_arg)]

use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::{
    prepare_g1, prepare_g2, AffineCurve, PairingEngine, ProjectiveCurve,
};
use ark_ff::{BigInteger256, Field, UniformRand};
use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion,
};
use itertools::izip;
use rand::prelude::StdRng;
use rand_core::SeedableRng;

type E = Bls12_381;
type G1Projective = ark_ec::bls12::G1Projective<ark_bls12_381::Parameters>;
type G1Affine = ark_ec::bls12::G1Affine<ark_bls12_381::Parameters>;
type G1Prepared = <E as PairingEngine>::G1Prepared;
type G2Projective = ark_ec::bls12::G2Projective<ark_bls12_381::Parameters>;
type G2Affine = ark_ec::bls12::G2Affine<ark_bls12_381::Parameters>;
type G2Prepared = <E as PairingEngine>::G2Prepared;
type Fqk = <E as PairingEngine>::Fqk;

pub fn bench_mul(c: &mut Criterion) {
    let mut rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("mul");

    let g1 = G1Projective::rand(&mut rng);
    let g2 = G2Projective::rand(&mut rng);
    let g1_affine = g1.into_affine();
    let g2_affine = g2.into_affine();
    let int = BigInteger256::rand(&mut rng);

    group.bench_function("G1Projective", |b| b.iter(|| g1.mul(int)));
    group.bench_function("G2Projective", |b| b.iter(|| g2.mul(int)));
    group.bench_function("G1Affine", |b| b.iter(|| g1_affine.mul(int)));
    group.bench_function("G2Affine", |b| b.iter(|| g2_affine.mul(int)));
}

pub fn bench_into_affine(c: &mut Criterion) {
    let mut rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("into_affine");

    let g1 = G1Projective::rand(&mut rng);
    let g2 = G2Projective::rand(&mut rng);

    group.bench_function("G1Projective", |b| b.iter(|| g1.into_affine()));
    group.bench_function("G2Projective", |b| b.iter(|| g2.into_affine()));
}

pub fn bench_into_projective(c: &mut Criterion) {
    let mut rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("into_projective");

    let g1_affine = G1Projective::rand(&mut rng).into_affine();
    let g2_affine = G2Projective::rand(&mut rng).into_affine();

    group
        .bench_function("G1Affine", |b| b.iter(|| g1_affine.into_projective()));
    group
        .bench_function("G2Affine", |b| b.iter(|| g2_affine.into_projective()));
}

pub fn bench_prepare_gx(c: &mut Criterion) {
    let mut rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("prepare_gx");

    let g1_affine = G1Projective::rand(&mut rng).into_affine();
    let g2_affine = G2Projective::rand(&mut rng).into_affine();

    group.bench_function("G1Affine", |b| b.iter(|| prepare_g1::<E>(g1_affine)));
    group.bench_function("G2Affine", |b| b.iter(|| prepare_g2::<E>(g2_affine)));
}

pub fn bench_pow(c: &mut Criterion) {
    let mut rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("pow");

    let fqk = Fqk::rand(&mut rng);
    let int = BigInteger256::rand(&mut rng);

    group.bench_function("Fqk", |b| b.iter(|| fqk.pow(int)));
}

fn make_prepared_pairing_inputs(
    size: usize,
    rng: &mut StdRng,
) -> Vec<(G1Prepared, G2Prepared)> {
    let (p, q) = make_pairing_inputs(size, rng);
    let pq = &p
        .iter()
        .zip(q.iter())
        .map(|(i, j)| (G1Prepared::from(*i), G2Prepared::from(*j)))
        .collect::<Vec<(G1Prepared, G2Prepared)>>();
    pq.to_vec()
}

fn make_pairing_inputs(
    size: usize,
    rng: &mut StdRng,
) -> (Vec<G1Affine>, Vec<G2Affine>) {
    let p = (0..size)
        .map(|_| {
            G1Affine::prime_subgroup_generator()
                .mul(Fr::rand(rng))
                .into_affine()
        })
        .collect::<Vec<G1Affine>>();
    let q = (0..size)
        .map(|_| {
            G2Affine::prime_subgroup_generator()
                .mul(Fr::rand(rng))
                .into_affine()
        })
        .collect::<Vec<G2Affine>>();
    (p, q)
}

pub fn bench_miller_loop(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("miller_loop");

    let cases = vec![1, 2, 4, 8, 16, 32, 64];
    let pq = make_prepared_pairing_inputs(cases[cases.len() - 1], rng);

    for nr_of_inputs in cases {
        group.bench_function(
            BenchmarkId::new("BLS12-381 miller_loop", nr_of_inputs),
            |b| b.iter(|| E::miller_loop(pq.iter().take(nr_of_inputs))),
        );
    }
}

pub fn bench_final_exponentiation(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("final_exponentiation");

    let cases = vec![1, 2, 4, 8, 16, 32, 64];
    let pq = make_prepared_pairing_inputs(cases[cases.len() - 1], rng);
    let ml = cases
        .iter()
        .map(|nr_of_inputs| {
            let pq = pq.iter().take(*nr_of_inputs).collect::<Vec<_>>();
            E::miller_loop(pq)
        })
        .collect::<Vec<_>>();

    for (ml, nr_of_inputs) in izip!(ml, cases) {
        group.bench_function(
            BenchmarkId::new("BLS12-381 final_exponentiation", nr_of_inputs),
            |b| b.iter(|| E::final_exponentiation(&ml)),
        );
    }
}

pub fn bench_pairing(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("pairing");

    let (p, q) = make_pairing_inputs(1, rng);

    group.bench_function("BLS12-381 pairing", |b| {
        b.iter(|| black_box(Bls12_381::pairing(p[0], q[0])))
    });
}

pub fn bench_product_of_pairings(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("product_of_pairings");
    group.sample_size(10);

    let cases = vec![1, 2, 4, 8, 16, 32, 64];
    let pq = make_prepared_pairing_inputs(cases[cases.len() - 1], rng);

    for nr_of_inputs in cases {
        group.bench_function(
            BenchmarkId::new("BLS12-381 product_of_pairings", nr_of_inputs),
            |b| {
                b.iter(|| {
                    black_box(Bls12_381::product_of_pairings(
                        pq.iter().take(nr_of_inputs),
                    ))
                })
            },
        );
    }
}

criterion_group!(
    benches,
    bench_mul,
    bench_into_affine,
    bench_into_projective,
    bench_prepare_gx,
    bench_pow,
    bench_miller_loop,
    bench_final_exponentiation,
    bench_pairing,
    bench_product_of_pairings,
);

criterion_main!(benches);
