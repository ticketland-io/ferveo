#![allow(unused_imports)]

pub mod dkg;
pub mod msg;
pub mod vss;

pub mod primitives;

use itertools::{izip, zip_eq};
pub use primitives::*;

use ferveo_common::Rng;

use crate::dkg::*;
use crate::msg::*;

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, Zero};
use ark_poly::{
    polynomial::univariate::DensePolynomial, polynomial::UVPolynomial,
    EvaluationDomain,
};
use ark_std::{end_timer, start_timer};
use serde::*;

use anyhow::{anyhow, Result};
pub use dkg::*;
pub use msg::*;
pub use vss::*;

use ark_ec::msm::FixedBaseMSM;
use ark_ec::PairingEngine;
use ark_ff::PrimeField;

use measure_time::print_time;

#[cfg(test)]
mod test_dkg_full {
    use super::*;

    use crate::dkg::pv::test_common::*;
    use ark_bls12_381::{
        Bls12_381 as E, Bls12_381, Fr, G1Affine, G2Projective,
    };
    use ark_ec::bls12::G2Affine;
    use ark_ec::group::Group;
    use ark_ff::{Fp12, UniformRand};
    use ark_std::test_rng;
    use ferveo_common::{ExternalValidator, Keypair};
    use group_threshold_cryptography as tpke;
    use group_threshold_cryptography::{Ciphertext, DecryptionShareSimple};
    use itertools::{zip_eq, Itertools};

    type Fqk = <E as PairingEngine>::Fqk;

    fn make_shared_secret_simple_tdec(
        dkg: &PubliclyVerifiableDkg<E>,
        aad: &[u8],
        ciphertext: &Ciphertext<E>,
        validator_keypairs: &[Keypair<E>],
    ) -> Fqk {
        // Make sure validators are in the same order dkg is by comparing their public keys
        dkg.validators
            .iter()
            .zip_eq(validator_keypairs.iter())
            .for_each(|(v, k)| {
                assert_eq!(v.validator.public_key, k.public());
            });

        let pvss_aggregated = aggregate(dkg);

        let decryption_shares: Vec<DecryptionShareSimple<E>> =
            validator_keypairs
                .iter()
                .enumerate()
                .map(|(validator_index, validator_keypair)| {
                    pvss_aggregated.make_decryption_share_simple(
                        ciphertext,
                        aad,
                        &validator_keypair.decryption_key,
                        validator_index,
                    )
                })
                .collect();

        let domain = &dkg
            .domain
            .elements()
            .take(decryption_shares.len())
            .collect::<Vec<_>>();
        assert_eq!(domain.len(), decryption_shares.len());

        // TODO: Consider refactor this part into tpke::combine_simple and expose it
        //  as a public API in tpke::api

        let lagrange_coeffs = tpke::prepare_combine_simple::<E>(domain);

        tpke::share_combine_simple::<E>(&decryption_shares, &lagrange_coeffs)
    }

    #[test]
    fn test_dkg_simple_decryption_variant_single_validator() {
        let rng = &mut test_rng();

        let dkg = setup_dealt_dkg_with_n_validators(1, 1);
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let public_key = dkg.final_key();
        let ciphertext = tpke::encrypt::<_, E>(msg, aad, &public_key, rng);
        let validator_keypairs = gen_n_keypairs(1);

        let shared_secret = make_shared_secret_simple_tdec(
            &dkg,
            aad,
            &ciphertext,
            &validator_keypairs,
        );

        let plaintext = tpke::checked_decrypt_with_shared_secret(
            &ciphertext,
            aad,
            &shared_secret,
        )
        .unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn test_dkg_simple_decryption_variant() {
        let rng = &mut test_rng();

        let dkg = setup_dealt_dkg_with_n_validators(3, 4);
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let public_key = dkg.final_key();
        let ciphertext = tpke::encrypt::<_, E>(msg, aad, &public_key, rng);
        let validator_keypairs = gen_n_keypairs(4);

        let shared_secret = make_shared_secret_simple_tdec(
            &dkg,
            aad,
            &ciphertext,
            &validator_keypairs,
        );

        let plaintext = tpke::checked_decrypt_with_shared_secret(
            &ciphertext,
            aad,
            &shared_secret,
        )
        .unwrap();
        assert_eq!(plaintext, msg);
    }

    #[test]
    fn test_dkg_simple_decryption_shares_verification() {
        let rng = &mut test_rng();

        let dkg = setup_dealt_dkg_with_n_validators(3, 4);
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let public_key = dkg.final_key();
        let ciphertext = tpke::encrypt::<_, E>(msg, aad, &public_key, rng);
        let validator_keypairs = gen_n_keypairs(4);

        let pvss_aggregated = aggregate(&dkg);

        let decryption_shares: Vec<DecryptionShareSimple<E>> =
            validator_keypairs
                .iter()
                .enumerate()
                .map(|(validator_index, validator_keypair)| {
                    pvss_aggregated.make_decryption_share_simple(
                        &ciphertext,
                        aad,
                        &validator_keypair.decryption_key,
                        validator_index,
                    )
                })
                .collect();

        // Testing green-path decryption share verification
        izip!(
            &pvss_aggregated.shares,
            &validator_keypairs,
            &decryption_shares,
        )
        .for_each(
            |(aggregated_share, validator_keypair, decryption_share)| {
                assert!(decryption_share.verify(
                    aggregated_share,
                    &validator_keypair.public().encryption_key,
                    &dkg.pvss_params.h,
                    &ciphertext,
                ));
            },
        );

        // Testing red-path decryption share verification
        let decryption_share = decryption_shares[0].clone();

        // Should fail because of the bad decryption share
        let mut with_bad_decryption_share = decryption_share.clone();
        with_bad_decryption_share.decryption_share = Fqk::zero();
        assert!(!with_bad_decryption_share.verify(
            &pvss_aggregated.shares[0],
            &validator_keypairs[0].public().encryption_key,
            &dkg.pvss_params.h,
            &ciphertext,
        ));

        // Should fail because of the bad checksum
        let mut with_bad_checksum = decryption_share;
        with_bad_checksum.validator_checksum = G1Affine::zero();
        assert!(!with_bad_checksum.verify(
            &pvss_aggregated.shares[0],
            &validator_keypairs[0].public().encryption_key,
            &dkg.pvss_params.h,
            &ciphertext,
        ));
    }

    // fn test_dkg_simple_decryption_variant_share_recovery() {
    //     let rng = &mut test_rng();
    //     let dkg = setup_dealt_dkg_with_n_validators(3, 4);
    //
    //     let msg: &[u8] = "abc".as_bytes();
    //     let aad: &[u8] = "my-aad".as_bytes();
    //     let public_key = dkg.final_key();
    //     let ciphertext = tpke::encrypt::<_, E>(msg, aad, &public_key, rng);
    //
    //     let validator_keypairs = gen_n_keypairs(4);
    //     // Make sure validators are in the same order dkg is by comparing their public keys
    //     dkg.validators
    //         .iter()
    //         .zip_eq(validator_keypairs.iter())
    //         .for_each(|(v, k)| {
    //             assert_eq!(v.validator.public_key, k.public());
    //         });
    //
    //     let pvss_aggregated = aggregate(&dkg);
    //
    //     let decryption_shares: Vec<DecryptionShareSimple<E>> =
    //         validator_keypairs
    //             .iter()
    //             .enumerate()
    //             .map(|(validator_index, validator_keypair)| {
    //                 pvss_aggregated.make_decryption_share_simple(
    //                     &ciphertext,
    //                     aad,
    //                     &validator_keypair.decryption_key,
    //                     validator_index,
    //                 )
    //             })
    //             .collect();
    //
    //     let domain = &dkg
    //         .domain
    //         .elements()
    //         .collect::<Vec<_>>();
    //     assert_eq!(domain.len(), decryption_shares.len());
    //     let lagrange_coeffs = tpke::prepare_combine_simple::<E>(domain);
    //
    //     // Create an initial shared secret
    //
    //     let old_shared_secret = tpke::share_combine_simple::<E>(
    //         &decryption_shares,
    //         &lagrange_coeffs,
    //     );
    //
    //     // Now, we're going to recover a new share at a random point and check that the shared secret is still the same
    //
    //     // Remove one participant from the contexts and all nested structure
    //     let mut new_dkg = dkg;
    //     let removed_validator = new_dkg.validators.pop().unwrap();
    //
    //     // Recover the share
    //     let x_r = Fr::rand(rng);
    //     let recovered_key_share = tpke::recover_private_key_share_at_point(
    //         &new_dkg.validators,
    //         new_dkg.params.security_threshold as usize,
    //         &x_r,
    //         rng,
    //     );
    //
    //     // Creating decryption shares
    //     let mut decryption_shares: Vec<_> = remaining_participants
    //         .iter()
    //         .map(|c| c.create_share(&ciphertext, aad).unwrap())
    //         .collect();
    //     decryption_shares.push(DecryptionShareSimple {
    //         decrypter_index: removed_participant.index,
    //         decryption_share: make_decryption_share(
    //             &recovered_key_share,
    //             &ciphertext,
    //         ),
    //         // TODO: Implement a method to make a proper decryption share after refreshing
    //         validator_checksum: G1Affine::zero(),
    //     });
    //
    //     // Creating a shared secret from remaining shares and the recovered one
    //     let new_shared_secret = make_shared_secret(
    //         &remaining_participants[0].public_decryption_contexts,
    //         &decryption_shares,
    //     );
    //
    //     assert_eq!(old_shared_secret, new_shared_secret);
    // }

    #[test]
    fn simple_threshold_decryption_with_share_refreshing() {
        let rng = &mut test_rng();
        let dkg = setup_dealt_dkg_with_n_validators(3, 4);

        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();
        let public_key = dkg.final_key();
        let ciphertext = tpke::encrypt::<_, E>(msg, aad, &public_key, rng);

        let validator_keypairs = gen_n_keypairs(4);
        let pvss_aggregated = aggregate(&dkg);

        // Create an initial shared secret
        let old_shared_secret = make_shared_secret_simple_tdec(
            &dkg,
            aad,
            &ciphertext,
            &validator_keypairs,
        );

        // Now, we're going to refresh the shares and check that the shared secret is the same

        // Dealer computes a new random polynomial with constant term x_r = 0
        let polynomial = tpke::make_random_polynomial_at::<E>(
            dkg.params.security_threshold as usize,
            &Fr::zero(),
            rng,
        );

        // Dealer shares the polynomial with participants

        // Participants computes new decryption shares
        let new_decryption_shares: Vec<DecryptionShareSimple<E>> =
            validator_keypairs
                .iter()
                .enumerate()
                .map(|(validator_index, validator_keypair)| {
                    pvss_aggregated.refresh_decryption_share(
                        &ciphertext,
                        aad,
                        &validator_keypair.decryption_key,
                        validator_index,
                        &polynomial,
                        &dkg,
                    )
                })
                .collect();

        // Create a new shared secret
        let domain = &dkg.domain.elements().collect::<Vec<_>>();
        let lagrange_coeffs = tpke::prepare_combine_simple::<E>(domain);
        let new_shared_secret = tpke::share_combine_simple::<E>(
            &new_decryption_shares,
            &lagrange_coeffs,
        );

        assert_eq!(old_shared_secret, new_shared_secret);
    }
}
