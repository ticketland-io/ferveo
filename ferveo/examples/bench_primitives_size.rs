use ark_serialize::CanonicalSerialize;

use ark_bls12_381::Bls12_381 as EllipticCurve;
use ferveo::*;
use ferveo_common::ExternalValidator;
use rand::prelude::StdRng;
use rand_core::SeedableRng;
use std::fs::{create_dir_all, OpenOptions};
use std::io::prelude::*;
use std::path::Path;

pub fn save_data(threshold: usize, shares_num: usize, transcript_size: usize) {
    let dir_path = Path::new("/tmp/benchmark_setup");
    create_dir_all(dir_path).unwrap();
    let file_path = dir_path.join("results.md");

    if !file_path.exists() {
        eprintln!("Creating a new file: {}", file_path.display());
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&file_path)
            .unwrap();
        writeln!(file, "|threshold|shares_num|pvss_transcript_size|",).unwrap();
        writeln!(file, "|---|---|---|",).unwrap();
    }

    eprintln!("Appending to file: {}", file_path.display());
    let mut file = OpenOptions::new().append(true).open(&file_path).unwrap();
    writeln!(file, "|{}|{}|{}|", threshold, shares_num, transcript_size,)
        .unwrap();
}

// TODO: Find a way to deduplicate the following methods with benchmarks and test setup

fn gen_keypairs(num: u32) -> Vec<ferveo_common::Keypair<EllipticCurve>> {
    let rng = &mut ark_std::test_rng();
    (0..num)
        .map(|_| ferveo_common::Keypair::<EllipticCurve>::new(rng))
        .collect()
}

fn gen_validators(
    keypairs: &[ferveo_common::Keypair<EllipticCurve>],
) -> Vec<ExternalValidator<EllipticCurve>> {
    (0..keypairs.len())
        .map(|i| ExternalValidator {
            address: format!("validator_{}", i),
            public_key: keypairs[i].public(),
        })
        .collect()
}

fn setup_dkg(
    validator: usize,
    shares_num: u32,
) -> PubliclyVerifiableDkg<EllipticCurve> {
    let keypairs = gen_keypairs(shares_num);
    let validators = gen_validators(&keypairs);
    let me = validators[validator].clone();
    PubliclyVerifiableDkg::new(
        validators,
        Params {
            tau: 0,
            security_threshold: shares_num / 3,
            shares_num,
            retry_after: 1,
        },
        &me,
        keypairs[validator],
    )
    .expect("Setup failed")
}

fn setup(
    shares_num: u32,
    rng: &mut StdRng,
) -> PubliclyVerifiableDkg<EllipticCurve> {
    let mut transcripts = vec![];
    for i in 0..shares_num {
        let mut dkg = setup_dkg(i as usize, shares_num);
        transcripts.push(dkg.share(rng).expect("Test failed"));
    }

    let mut dkg = setup_dkg(0, shares_num);
    for (sender, pvss) in transcripts.into_iter().enumerate() {
        dkg.apply_message(dkg.validators[sender].validator.clone(), pvss)
            .expect("Setup failed");
    }
    dkg
}

fn main() {
    let rng = &mut StdRng::seed_from_u64(0);

    for shares_num in [2, 4, 8, 16, 32, 64] {
        let dkg = setup(shares_num as u32, rng);
        let mut transcript_bytes = vec![];
        dkg.vss[&0].serialize(&mut transcript_bytes).unwrap();

        save_data(
            dkg.params.security_threshold as usize,
            shares_num,
            transcript_bytes.len(),
        );
    }
}
