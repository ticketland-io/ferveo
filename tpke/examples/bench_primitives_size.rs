use ark_serialize::CanonicalSerialize;
use group_threshold_cryptography::{
    encrypt, prepare_combine_simple, setup_simple, share_combine_simple,
};
use rand_core::RngCore;
use std::fs::{create_dir_all, OpenOptions};
use std::io::prelude::*;
use std::path::Path;

pub fn update_benchmark(
    threshold: usize,
    shares_num: usize,
    pubkey_share_serialized_size: usize,
    privkey_share_serialized_size: usize,
) {
    let dir_path = Path::new("/tmp/benchmark_setup");
    create_dir_all(dir_path).unwrap();

    let file_path = dir_path.join("results.md");
    eprintln!("Saving setup results to file: {}", file_path.display());

    if !file_path.exists() {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&file_path)
            .unwrap();

        writeln!(
            file,
            "|threshold|shares_num|pubkey_share_serialized_size|privkey_share_serialized_size|",
        )
            .unwrap();

        writeln!(file, "|---|---|---|---|",).unwrap();
    }

    let mut file = OpenOptions::new().append(true).open(&file_path).unwrap();

    writeln!(
        file,
        "|{}|{}|{}|{}|",
        threshold,
        shares_num,
        pubkey_share_serialized_size,
        privkey_share_serialized_size,
    )
    .unwrap();
}

type E = ark_bls12_381::Bls12_381;

fn main() {
    for shares_num in [2, 4, 8, 16, 32, 64] {
        let rng = &mut rand::thread_rng();

        let msg_size = 256;
        let threshold = shares_num * 2 / 3;

        let mut msg: Vec<u8> = vec![0u8; msg_size];
        rng.fill_bytes(&mut msg[..]);
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _privkey, contexts) =
            setup_simple::<E>(threshold, shares_num, rng);

        // Ciphertext.commitment is already computed to match U
        let ciphertext = encrypt::<_, E>(&msg, aad, &pubkey, rng);

        // Creating decryption shares
        let decryption_shares: Vec<_> = contexts
            .iter()
            .map(|context| context.create_share(&ciphertext))
            .collect();

        let pub_contexts = &contexts[0].public_decryption_contexts;
        let domain: Vec<_> = pub_contexts.iter().map(|c| c.domain).collect();
        let lagrange = prepare_combine_simple::<E>(&domain);

        let _shared_secret =
            share_combine_simple::<E>(&decryption_shares, &lagrange);

        let pub_context = &contexts[0].public_decryption_contexts[0];

        update_benchmark(
            threshold,
            shares_num,
            pub_context
                .public_key_share
                .public_key_share
                .serialized_size(),
            contexts[0]
                .private_key_share
                .private_key_share
                .serialized_size(),
        );
    }
}
