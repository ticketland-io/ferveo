use crate::hash_to_curve::htp_bls12381_g2;
use crate::SetupParams;

use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::{Field, One, PrimeField, ToBytes, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Polynomial, UVPolynomial,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use itertools::izip;

use subproductdomain::SubproductDomain;

use rand_core::RngCore;
use std::usize;
use thiserror::Error;

mod ciphertext;
mod combine;
mod context;
mod decryption;
mod hash_to_curve;
mod key_share;
mod refresh;

pub use ciphertext::*;
pub use combine::*;
pub use context::*;
pub use decryption::*;
pub use key_share::*;
pub use refresh::*;

// TODO: Turn into a crate features
pub mod api;
pub mod serialization;

pub trait ThresholdEncryptionParameters {
    type E: PairingEngine;
}

#[derive(Debug, Error)]
pub enum ThresholdEncryptionError {
    /// Error
    #[error("ciphertext verification failed")]
    CiphertextVerificationFailed,

    /// Error
    #[error("Decryption share verification failed")]
    DecryptionShareVerificationFailed,

    /// Hashing to curve failed
    #[error("Could not hash to curve")]
    HashToCurveError,

    #[error("plaintext verification failed")]
    PlaintextVerificationFailed,
}

pub type Result<T> = std::result::Result<T, ThresholdEncryptionError>;

fn hash_to_g2<T: ark_serialize::CanonicalDeserialize>(message: &[u8]) -> T {
    let mut point_ser: Vec<u8> = Vec::new();
    let point = htp_bls12381_g2(message);
    point.serialize(&mut point_ser).unwrap();
    T::deserialize(&point_ser[..]).unwrap()
}

fn construct_tag_hash<E: PairingEngine>(
    u: E::G1Affine,
    stream_ciphertext: &[u8],
    aad: &[u8],
) -> E::G2Affine {
    let mut hash_input = Vec::<u8>::new();
    u.write(&mut hash_input).unwrap();
    hash_input.extend_from_slice(stream_ciphertext);
    hash_input.extend_from_slice(aad);

    hash_to_g2(&hash_input)
}

pub fn setup_fast<E: PairingEngine>(
    threshold: usize,
    shares_num: usize,
    rng: &mut impl RngCore,
) -> (
    E::G1Affine,
    E::G2Affine,
    Vec<PrivateDecryptionContextFast<E>>,
) {
    assert!(shares_num >= threshold);

    // Generators G∈G1, H∈G2
    let g = E::G1Affine::prime_subgroup_generator();
    let h = E::G2Affine::prime_subgroup_generator();

    // The dealer chooses a uniformly random polynomial f of degree t-1
    let threshold_poly = DensePolynomial::<E::Fr>::rand(threshold - 1, rng);
    // Domain, or omega Ω
    let fft_domain =
        ark_poly::Radix2EvaluationDomain::<E::Fr>::new(shares_num).unwrap();
    // `evals` are evaluations of the polynomial f over the domain, omega: f(ω_j) for ω_j in Ω
    let evals = threshold_poly.evaluate_over_domain_by_ref(fft_domain);

    let mut domain_points = Vec::with_capacity(shares_num);
    let mut point = E::Fr::one();
    let mut domain_points_inv = Vec::with_capacity(shares_num);
    let mut point_inv = E::Fr::one();

    for _ in 0..shares_num {
        domain_points.push(point); // 1, t, t^2, t^3, ...; where t is a scalar generator fft_domain.group_gen
        point *= fft_domain.group_gen;
        domain_points_inv.push(point_inv);
        point_inv *= fft_domain.group_gen_inv;
    }

    let scalar_bits = E::Fr::size_in_bits();

    // A - public key shares of participants
    let pubkey_shares =
        subproductdomain::fast_multiexp(&evals.evals, g.into_projective());
    let pubkey_share = g.mul(evals.evals[0]);
    debug_assert!(pubkey_shares[0] == E::G1Affine::from(pubkey_share));

    // Y, but only when b = 1 - private key shares of participants
    let privkey_shares =
        subproductdomain::fast_multiexp(&evals.evals, h.into_projective());

    // a_0
    let x = threshold_poly.coeffs[0];

    // F_0 - The commitment to the constant term, and is the public key output Y from PVDKG
    let pubkey = g.mul(x);
    let privkey = h.mul(x);

    let mut private_contexts = vec![];
    let mut public_contexts = vec![];

    // (domain, domain_inv, A, Y)
    for (index, (domain, domain_inv, public, private)) in izip!(
        domain_points.iter(),
        domain_points_inv.iter(),
        pubkey_shares.iter(),
        privkey_shares.iter()
    )
    .enumerate()
    {
        let private_key_share = PrivateKeyShare::<E> {
            private_key_share: *private,
        };
        let b = E::Fr::rand(rng);
        let mut blinded_key_shares = private_key_share.blind(b);
        blinded_key_shares.multiply_by_omega_inv(domain_inv);
        private_contexts.push(PrivateDecryptionContextFast::<E> {
            index,
            setup_params: SetupParams {
                b,
                b_inv: b.inverse().unwrap(),
                g,
                g_inv: E::G1Prepared::from(-g),
                h_inv: E::G2Prepared::from(-h),
                h,
            },
            private_key_share,
            public_decryption_contexts: vec![],
            scalar_bits,
        });
        public_contexts.push(PublicDecryptionContextFast::<E> {
            domain: *domain,
            public_key_share: PublicKeyShare::<E> {
                public_key_share: *public,
            },
            blinded_key_share: blinded_key_shares,
            lagrange_n_0: *domain,
        });
    }
    for private in private_contexts.iter_mut() {
        private.public_decryption_contexts = public_contexts.clone();
    }

    (pubkey.into(), privkey.into(), private_contexts)
}

pub fn setup_simple<E: PairingEngine>(
    threshold: usize,
    shares_num: usize,
    rng: &mut impl RngCore,
) -> (
    E::G1Affine,
    E::G2Affine,
    Vec<PrivateDecryptionContextSimple<E>>,
) {
    assert!(shares_num >= threshold);

    let g = E::G1Affine::prime_subgroup_generator();
    let h = E::G2Affine::prime_subgroup_generator();

    // The dealer chooses a uniformly random polynomial f of degree t-1
    let threshold_poly = DensePolynomial::<E::Fr>::rand(threshold - 1, rng);
    // Domain, or omega Ω
    let fft_domain =
        ark_poly::Radix2EvaluationDomain::<E::Fr>::new(shares_num).unwrap();
    // `evals` are evaluations of the polynomial f over the domain, omega: f(ω_j) for ω_j in Ω
    let evals = threshold_poly.evaluate_over_domain_by_ref(fft_domain);

    let shares_x = fft_domain.elements().collect::<Vec<_>>();

    // A - public key shares of participants
    let pubkey_shares =
        subproductdomain::fast_multiexp(&evals.evals, g.into_projective());
    let pubkey_share = g.mul(evals.evals[0]);
    assert!(pubkey_shares[0] == E::G1Affine::from(pubkey_share));

    // Y, but only when b = 1 - private key shares of participants
    let privkey_shares =
        subproductdomain::fast_multiexp(&evals.evals, h.into_projective());

    // a_0
    let x = threshold_poly.coeffs[0];
    // F_0
    let pubkey = g.mul(x);
    let privkey = h.mul(x);

    let secret = threshold_poly.evaluate(&E::Fr::zero());
    assert_eq!(secret, x);

    let mut private_contexts = vec![];
    let mut public_contexts = vec![];

    // (domain, A, Y)
    for (index, (domain, public, private)) in
        izip!(shares_x.iter(), pubkey_shares.iter(), privkey_shares.iter())
            .enumerate()
    {
        let private_key_share = PrivateKeyShare::<E> {
            private_key_share: *private,
        };
        let b = E::Fr::rand(rng);
        let blinded_key_shares = private_key_share.blind(b);
        private_contexts.push(PrivateDecryptionContextSimple::<E> {
            index,
            setup_params: SetupParams {
                b,
                b_inv: b.inverse().unwrap(),
                g,
                g_inv: E::G1Prepared::from(-g),
                h_inv: E::G2Prepared::from(-h),
                h,
            },
            private_key_share,
            public_decryption_contexts: vec![],
        });
        public_contexts.push(PublicDecryptionContextSimple::<E> {
            domain: *domain,
            public_key_share: PublicKeyShare::<E> {
                public_key_share: *public,
            },
            blinded_key_share: blinded_key_shares,
        });
    }
    for private in private_contexts.iter_mut() {
        private.public_decryption_contexts = public_contexts.clone();
    }

    (pubkey.into(), privkey.into(), private_contexts)
}

pub fn generate_random<R: RngCore, E: PairingEngine>(
    n: usize,
    rng: &mut R,
) -> Vec<E::Fr> {
    (0..n).map(|_| E::Fr::rand(rng)).collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use crate::*;
    use ark_bls12_381::Fr;
    use ark_ec::ProjectiveCurve;
    use ark_std::test_rng;
    use rand::prelude::StdRng;

    type E = ark_bls12_381::Bls12_381;

    #[test]
    fn ciphertext_serialization() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, _) = setup_fast::<E>(threshold, shares_num, rng);

        let ciphertext = encrypt::<StdRng, E>(msg, aad, &pubkey, rng);

        let serialized = ciphertext.to_bytes();
        let deserialized: Ciphertext<E> = Ciphertext::from_bytes(&serialized);

        assert_eq!(serialized, deserialized.to_bytes())
    }

    #[test]
    fn symmetric_encryption() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, privkey, _) = setup_fast::<E>(threshold, shares_num, rng);

        let ciphertext = encrypt::<StdRng, E>(msg, aad, &pubkey, rng);

        let plaintext = checked_decrypt(&ciphertext, aad, privkey).unwrap();

        assert_eq!(msg, plaintext)
    }

    fn test_ciphertext_validation_fails<E: PairingEngine>(
        msg: &[u8],
        aad: &[u8],
        ciphertext: &Ciphertext<E>,
        shared_secret: &E::Fqk,
    ) {
        // So far, the ciphertext is valid
        let plaintext =
            checked_decrypt_with_shared_secret(ciphertext, aad, shared_secret)
                .unwrap();
        assert_eq!(plaintext, msg);

        // Malformed the ciphertext
        let mut ciphertext = ciphertext.clone();
        ciphertext.ciphertext[0] += 1;
        assert!(checked_decrypt_with_shared_secret(
            &ciphertext,
            aad,
            shared_secret,
        )
        .is_err());

        // Malformed the AAD
        let aad = "bad aad".as_bytes();
        assert!(checked_decrypt_with_shared_secret(
            &ciphertext,
            aad,
            shared_secret,
        )
        .is_err());
    }

    #[test]
    fn ciphertext_validity_check() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, _) = setup_fast::<E>(threshold, shares_num, rng);
        let mut ciphertext = encrypt::<StdRng, E>(msg, aad, &pubkey, rng);

        // So far, the ciphertext is valid
        assert!(check_ciphertext_validity(&ciphertext, aad).is_ok());

        // Malformed the ciphertext
        ciphertext.ciphertext[0] += 1;
        assert!(check_ciphertext_validity(&ciphertext, aad).is_err());

        // Malformed the AAD
        let aad = "bad aad".as_bytes();
        assert!(check_ciphertext_validity(&ciphertext, aad).is_err());
    }

    #[test]
    fn fast_decryption_share_validation() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) = setup_fast::<E>(threshold, shares_num, rng);
        let ciphertext = encrypt::<StdRng, E>(msg, aad, &pubkey, rng);

        let bad_aad = "bad aad".as_bytes();
        assert!(contexts[0].create_share(&ciphertext, bad_aad).is_err());
    }

    #[test]
    fn simple_decryption_share_validation() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_simple::<E>(threshold, shares_num, rng);
        let ciphertext = encrypt::<StdRng, E>(msg, aad, &pubkey, rng);

        let bad_aad = "bad aad".as_bytes();
        assert!(contexts[0].create_share(&ciphertext, bad_aad).is_err());
    }

    #[test]
    fn fast_threshold_encryption() {
        let mut rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_fast::<E>(threshold, shares_num, &mut rng);
        let ciphertext = encrypt::<_, E>(msg, aad, &pubkey, rng);

        let mut shares: Vec<DecryptionShareFast<E>> = vec![];
        for context in contexts.iter() {
            shares.push(context.create_share(&ciphertext, aad).unwrap());
        }

        // TODO: Verify and enable this check
        /*for pub_context in contexts[0].public_decryption_contexts.iter() {
            assert!(pub_context
                .blinded_key_shares
                .verify_blinding(&pub_context.public_key_shares, rng));
        }*/
        let prepared_blinded_key_shares = prepare_combine_fast(
            &contexts[0].public_decryption_contexts,
            &shares,
        );
        let shared_secret =
            share_combine_fast(&shares, &prepared_blinded_key_shares);

        test_ciphertext_validation_fails(msg, aad, &ciphertext, &shared_secret);
    }

    #[test]
    fn simple_threshold_decryption() {
        let mut rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_simple::<E>(threshold, shares_num, &mut rng);

        // Ciphertext.commitment is already computed to match U
        let ciphertext = encrypt::<_, E>(msg, aad, &pubkey, rng);

        // Create decryption shares
        let decryption_shares: Vec<_> = contexts
            .iter()
            .map(|c| c.create_share(&ciphertext, aad).unwrap())
            .collect();
        let domain = contexts[0]
            .public_decryption_contexts
            .iter()
            .map(|c| c.domain)
            .collect::<Vec<_>>();
        let lagrange = prepare_combine_simple::<E>(&domain);

        let shared_secret =
            share_combine_simple::<E>(&decryption_shares, &lagrange);

        test_ciphertext_validation_fails(msg, aad, &ciphertext, &shared_secret);
    }

    #[test]
    /// Ñ parties (where t <= Ñ <= N) jointly execute a "share recovery" algorithm, and the output is 1 new share.
    /// The new share is intended to restore a previously existing share, e.g., due to loss or corruption.
    fn simple_threshold_decryption_with_share_recovery_at_selected_point() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;

        let (_, _, mut contexts) =
            setup_simple::<E>(threshold, shares_num, rng);

        // Prepare participants

        // First, save the soon-to-be-removed participant
        let selected_participant = contexts.pop().unwrap();
        let x_r = selected_participant
            .public_decryption_contexts
            .last()
            .unwrap()
            .domain;
        let original_y_r =
            selected_participant.private_key_share.private_key_share;

        // Now, we have to remove the participant from the contexts and all nested structures
        let mut remaining_participants = contexts;
        for p in &mut remaining_participants {
            p.public_decryption_contexts.pop();
        }

        // Recover the share
        let y_r = recover_share_at_point(
            &remaining_participants,
            threshold,
            &x_r,
            rng,
        );
        assert_eq!(y_r.into_affine(), original_y_r);
    }

    fn make_shared_secret_from_contexts<E: PairingEngine>(
        contexts: &[PrivateDecryptionContextSimple<E>],
        ciphertext: &Ciphertext<E>,
        aad: &[u8],
    ) -> E::Fqk {
        let decryption_shares: Vec<_> = contexts
            .iter()
            .map(|c| c.create_share(ciphertext, aad).unwrap())
            .collect();
        make_shared_secret(
            &contexts[0].public_decryption_contexts,
            &decryption_shares,
        )
    }

    fn make_shared_secret<E: PairingEngine>(
        pub_contexts: &[PublicDecryptionContextSimple<E>],
        decryption_shares: &[DecryptionShareSimple<E>],
    ) -> E::Fqk {
        let domain = pub_contexts.iter().map(|c| c.domain).collect::<Vec<_>>();
        let lagrange = prepare_combine_simple::<E>(&domain);
        share_combine_simple::<E>(decryption_shares, &lagrange)
    }

    fn make_decryption_share<E: PairingEngine>(
        private_share: &PrivateKeyShare<E>,
        ciphertext: &Ciphertext<E>,
    ) -> E::Fqk {
        let z_i = private_share;
        let u = ciphertext.commitment;
        let z_i = z_i.private_key_share;
        E::pairing(u, z_i)
    }

    #[test]
    /// Ñ parties (where t <= Ñ <= N) jointly execute a "share recovery" algorithm, and the output is 1 new share.
    /// The new share is independent from the previously existing shares. We can use this to on-board a new participant into an existing cohort.
    fn simple_threshold_decryption_with_share_recovery_at_random_point() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_simple::<E>(threshold, shares_num, rng);
        let ciphertext = encrypt::<_, E>(msg, aad, &pubkey, rng);

        // Create an initial shared secret
        let old_shared_secret =
            make_shared_secret_from_contexts(&contexts, &ciphertext, aad);

        // Now, we're going to recover a new share at a random point and check that the shared secret is still the same

        // Remove one participant from the contexts and all nested structures
        let mut remaining_participants = contexts;
        let removed_participant = remaining_participants.pop().unwrap();
        for p in &mut remaining_participants {
            p.public_decryption_contexts.pop().unwrap();
        }

        // Recover the share
        let x_r = Fr::rand(rng);
        let y_r = recover_share_at_point(
            &remaining_participants,
            threshold,
            &x_r,
            rng,
        );
        let recovered_key_share = PrivateKeyShare {
            private_key_share: y_r.into_affine(),
        };

        // Creating decryption shares
        let mut decryption_shares: Vec<_> = remaining_participants
            .iter()
            .map(|c| c.create_share(&ciphertext, aad).unwrap())
            .collect();
        decryption_shares.push(DecryptionShareSimple {
            decrypter_index: removed_participant.index,
            decryption_share: make_decryption_share(
                &recovered_key_share,
                &ciphertext,
            ),
        });

        // Creating a shared secret from remaining shares and the recovered one
        let new_shared_secret = make_shared_secret(
            &remaining_participants[0].public_decryption_contexts,
            &decryption_shares,
        );

        assert_eq!(old_shared_secret, new_shared_secret);
    }

    /// Ñ parties (where t <= Ñ <= N) jointly execute a "share refresh" algorithm.
    /// The output is M new shares (with M <= Ñ), with each of the M new shares substituting the
    /// original share (i.e., the original share is deleted).
    #[test]
    fn simple_threshold_decryption_with_share_refreshing() {
        let rng = &mut test_rng();
        let shares_num = 16;
        let threshold = shares_num * 2 / 3;
        let msg: &[u8] = "abc".as_bytes();
        let aad: &[u8] = "my-aad".as_bytes();

        let (pubkey, _, contexts) =
            setup_simple::<E>(threshold, shares_num, rng);
        let pub_contexts = contexts[0].public_decryption_contexts.clone();
        let ciphertext = encrypt::<_, E>(msg, aad, &pubkey, rng);

        // Create an initial shared secret
        let old_shared_secret =
            make_shared_secret_from_contexts(&contexts, &ciphertext, aad);

        // Now, we're going to refresh the shares and check that the shared secret is the same

        // Refresh shares
        let new_shares = refresh_shares::<E>(&contexts, threshold, rng);

        // Creating new decryption shares
        let new_decryption_shares: Vec<_> = new_shares
            .iter()
            .enumerate()
            .map(|(decrypter_index, private_share)| {
                let private_share = PrivateKeyShare {
                    private_key_share: private_share.into_affine(),
                };
                let decryption_share =
                    make_decryption_share(&private_share, &ciphertext);
                DecryptionShareSimple {
                    decrypter_index,
                    decryption_share,
                }
            })
            .collect();

        let new_shared_secret =
            make_shared_secret(&pub_contexts, &new_decryption_shares);

        assert_eq!(old_shared_secret, new_shared_secret);
    }
}
