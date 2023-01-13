#![allow(clippy::redundant_closure)]

use ark_bls12_381::{Fr, G1Affine, G2Affine};

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion,
};
use group_threshold_cryptography::*;
use rand::prelude::StdRng;
use rand_core::{RngCore, SeedableRng};

const SHARES_NUM_CASES: [usize; 5] = [4, 8, 16, 32, 64];
const MSG_SIZE_CASES: [usize; 7] = [256, 512, 1024, 2048, 4096, 8192, 16384];

type E = ark_bls12_381::Bls12_381;
type G2Prepared = ark_ec::bls12::G2Prepared<ark_bls12_381::Parameters>;
type Fqk = <ark_bls12_381::Bls12_381 as ark_ec::PairingEngine>::Fqk;

#[allow(dead_code)]
struct SetupShared {
    threshold: usize,
    shares_num: usize,
    msg: Vec<u8>,
    aad: Vec<u8>,
    pubkey: G1Affine,
    privkey: G2Affine,
    ciphertext: Ciphertext<E>,
    shared_secret: Fqk,
}

struct SetupFast {
    shared: SetupShared,
    contexts: Vec<PrivateDecryptionContextFast<E>>,
    pub_contexts: Vec<PublicDecryptionContextFast<E>>,
    decryption_shares: Vec<DecryptionShareFast<E>>,
    prepared_key_shares: Vec<G2Prepared>,
}

impl SetupFast {
    pub fn new(shares_num: usize, msg_size: usize, rng: &mut StdRng) -> Self {
        let threshold = shares_num * 2 / 3;
        let mut msg: Vec<u8> = vec![0u8; msg_size];
        rng.fill_bytes(&mut msg[..]);
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, privkey, contexts) =
            setup_fast::<E>(threshold, shares_num, rng);
        let ciphertext = encrypt::<_, E>(&msg, aad, &pubkey, rng);

        let mut decryption_shares: Vec<DecryptionShareFast<E>> = vec![];
        for context in contexts.iter() {
            decryption_shares.push(context.create_share(&ciphertext));
        }

        let pub_contexts = contexts[0].clone().public_decryption_contexts;
        let prepared_key_shares =
            prepare_combine_fast(&pub_contexts, &decryption_shares);

        let shared_secret =
            share_combine_fast(&decryption_shares, &prepared_key_shares);

        let shared_secret =
            share_combine_fast(&decryption_shares, &prepared_key_shares);

        let shared = SetupShared {
            threshold,
            shares_num,
            msg: msg.to_vec(),
            aad: aad.to_vec(),
            pubkey,
            privkey,
            ciphertext,
            shared_secret,
        };
        Self {
            shared,
            contexts,
            pub_contexts,
            decryption_shares,
            prepared_key_shares,
        }
    }
}

struct SetupSimple {
    shared: SetupShared,
    contexts: Vec<PrivateDecryptionContextSimple<E>>,
    pub_contexts: Vec<PublicDecryptionContextSimple<E>>,
    decryption_shares: Vec<DecryptionShareSimple<E>>,
    lagrange: Vec<Fr>,
}

impl SetupSimple {
    pub fn new(shares_num: usize, msg_size: usize, rng: &mut StdRng) -> Self {
        let threshold = shares_num * 2 / 3;
        let mut msg: Vec<u8> = vec![0u8; msg_size];
        rng.fill_bytes(&mut msg[..]);
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, privkey, contexts) =
            setup_simple::<E>(threshold, shares_num, rng);

        // Ciphertext.commitment is already computed to match U
        let ciphertext = encrypt::<_, E>(&msg, aad, &pubkey, rng);

        // Creating decryption shares
        let decryption_shares: Vec<_> = contexts
            .iter()
            .map(|context| context.create_share(&ciphertext))
            .collect();

        let pub_contexts = contexts[0].clone().public_decryption_contexts;
        let lagrange = prepare_combine_simple::<E>(&pub_contexts);

        let shared_secret =
            share_combine_simple::<E>(&decryption_shares, &lagrange);

        let shared = SetupShared {
            threshold,
            shares_num,
            msg: msg.to_vec(),
            aad: aad.to_vec(),
            pubkey,
            privkey,
            ciphertext,
            shared_secret,
        };
        Self {
            shared,
            contexts,
            pub_contexts,
            decryption_shares,
            lagrange,
        }
    }
}

pub fn bench_create_decryption_share(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("SHARE CREATE");
    group.sample_size(10);

    let msg_size = MSG_SIZE_CASES[0];

    for shares_num in SHARES_NUM_CASES {
        let fast = {
            let setup = SetupFast::new(shares_num, msg_size, rng);
            move || {
                black_box({
                    // TODO: Consider running benchmarks for a single iteration and not for all iterations.
                    // This way we could test the performance of this method for a single participant.
                    setup
                        .contexts
                        .iter()
                        .map(|ctx| ctx.create_share(&setup.shared.ciphertext))
                        .collect::<Vec<_>>()
                })
            }
        };
        let simple = {
            let setup = SetupSimple::new(shares_num, msg_size, rng);
            move || {
                black_box({
                    // TODO: Consider running benchmarks for a single iteration and not for all iterations.
                    // This way we could test the performance of this method for a single participant.
                    setup
                        .contexts
                        .iter()
                        .map(|ctx| ctx.create_share(&setup.shared.ciphertext))
                        .collect::<Vec<_>>()
                })
            }
        };

        group.bench_function(
            BenchmarkId::new("share_create_fast", shares_num),
            |b| b.iter(|| fast()),
        );
        group.bench_function(
            BenchmarkId::new("share_create_simple", shares_num),
            |b| b.iter(|| simple()),
        );
    }
}

pub fn bench_share_prepare(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("SHARE PREPARE");
    group.sample_size(10);
    let msg_size = MSG_SIZE_CASES[0];

    for shares_num in SHARES_NUM_CASES {
        let fast = {
            let setup = SetupFast::new(shares_num, msg_size, rng);
            move || {
                black_box(prepare_combine_fast(
                    &setup.pub_contexts,
                    &setup.decryption_shares,
                ))
            }
        };
        let simple = {
            let setup = SetupSimple::new(shares_num, msg_size, rng);
            move || black_box(prepare_combine_simple(&setup.pub_contexts))
        };

        group.bench_function(
            BenchmarkId::new("share_prepare_fast", shares_num),
            |b| b.iter(|| fast()),
        );
        group.bench_function(
            BenchmarkId::new("share_prepare_simple", shares_num),
            |b| b.iter(|| simple()),
        );
    }
}

pub fn bench_share_combine(c: &mut Criterion) {
    let rng = &mut StdRng::seed_from_u64(0);

    let mut group = c.benchmark_group("SHARE COMBINE");
    group.sample_size(10);

    let msg_size = MSG_SIZE_CASES[0];

    for shares_num in SHARES_NUM_CASES {
        let fast = {
            let setup = SetupFast::new(shares_num, msg_size, rng);
            move || {
                black_box(share_combine_fast(
                    &setup.decryption_shares,
                    &setup.prepared_key_shares,
                ));
            }
        };
        let simple = {
            let setup = SetupSimple::new(shares_num, msg_size, rng);
            move || {
                black_box(share_combine_simple::<E>(
                    &setup.decryption_shares,
                    &setup.lagrange,
                ));
            }
        };

    let mut group = c.benchmark_group("TPKE_SIMPLE");
    group.sample_size(10);
    group.measurement_time(core::time::Duration::new(30, 0));

    for num_shares in NUM_SHARES_CASES {
        let a = share_combine_bench(num_shares);
        group.bench_function(
            BenchmarkId::new("share_combine_fast", shares_num),
            |b| b.iter(|| fast()),
        );
        group.bench_function(
            BenchmarkId::new("share_combine_simple", shares_num),
            |b| b.iter(|| simple()),
        );
    }
}

pub fn bench_share_encrypt_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("ENCRYPT DECRYPT");
    group.sample_size(10);

    let rng = &mut StdRng::seed_from_u64(0);
    let shares_num = SHARES_NUM_CASES[0];

    for msg_size in MSG_SIZE_CASES {
        let mut encrypt = {
            let mut rng = rng.clone();
            let setup = SetupFast::new(shares_num, msg_size, &mut rng);
            move || {
                black_box(encrypt::<_, E>(
                    &setup.shared.msg,
                    &setup.shared.aad,
                    &setup.shared.pubkey,
                    &mut rng,
                ));
            }
        };
        let decrypt = {
            let setup = SetupSimple::new(shares_num, msg_size, rng);
            move || {
                black_box(
                    checked_decrypt_with_shared_secret::<E>(
                        &setup.shared.ciphertext,
                        &setup.shared.aad,
                        &setup.shared.shared_secret,
                    )
                    .unwrap(),
                );
            }
        };

        group.bench_function(BenchmarkId::new("encrypt", msg_size), |b| {
            b.iter(|| encrypt())
        });
        group.bench_function(BenchmarkId::new("decrypt", msg_size), |b| {
            b.iter(|| decrypt())
        });
    }
}

criterion_group!(
    benches,
    bench_create_decryption_share,
    bench_share_prepare,
    bench_share_combine,
    bench_share_encrypt_decrypt,
    bench_random_poly
);

criterion_main!(benches);
