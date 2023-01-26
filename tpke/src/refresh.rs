use crate::{
    lagrange_basis_at, PrivateDecryptionContextSimple, PrivateKeyShare,
};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use itertools::zip_eq;
use rand_core::RngCore;
use std::collections::HashMap;
use std::usize;

/// From PSS paper, section 4.2.1, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
pub fn prepare_share_updates_for_recovery<E: PairingEngine>(
    participants: &[PrivateDecryptionContextSimple<E>],
    x_r: &E::Fr,
    threshold: usize,
    rng: &mut impl RngCore,
) -> HashMap<usize, E::G2Projective> {
    // Generate a new random polynomial with constant term x_r
    let d_i = make_random_polynomial_at::<E>(threshold, x_r, rng);

    // Now, we need to evaluate the polynomial at each of participants' indices
    compute_polynomial_deltas::<E>(participants, &d_i)
}

/// From PSS paper, section 4.2.3, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
pub fn update_share_for_recovery<E: PairingEngine>(
    participant: &PrivateDecryptionContextSimple<E>,
    share_updates: &[E::G2Projective],
) -> E::G2Projective {
    let mut new_y = E::G2Projective::from(
        participant.private_key_share.private_key_share, // y_i
    );
    for delta in share_updates {
        new_y += delta; // y_i + delta_i
    }
    new_y
}

/// From the PSS paper, section 4.2.4, (https://link.springer.com/content/pdf/10.1007/3-540-44750-4_27.pdf)
pub fn recover_share_from_fragments<E: PairingEngine>(
    x_r: &E::Fr,
    domain_points: &[E::Fr],
    new_share_fragments: Vec<E::G2Projective>,
) -> PrivateKeyShare<E> {
    // Interpolate new shares to recover y_r
    let lagrange = lagrange_basis_at::<E>(domain_points, x_r);
    let prods = zip_eq(new_share_fragments, lagrange)
        .map(|(y_j, l)| y_j.mul(l.into_repr()));
    let y_r = prods.fold(E::G2Projective::zero(), |acc, y_j| acc + y_j);

    PrivateKeyShare {
        private_key_share: y_r.into_affine(),
    }
}

pub fn make_random_polynomial_at<E: PairingEngine>(
    threshold: usize,
    root: &E::Fr,
    rng: &mut impl RngCore,
) -> DensePolynomial<E::Fr> {
    // [][threshold-1]
    let mut threshold_poly = DensePolynomial::<E::Fr>::rand(threshold - 1, rng);

    // [0..][threshold]
    threshold_poly[0] = E::Fr::zero();

    // Now, we calculate d_i_0
    // This is the term that will "zero out" the polynomial at x_r, d_i(x_r) = 0
    let d_i_0 = E::Fr::zero() - threshold_poly.evaluate(root);
    threshold_poly[0] = d_i_0;

    debug_assert!(threshold_poly.evaluate(root) == E::Fr::zero());
    debug_assert!(threshold_poly.coeffs.len() == threshold);

    threshold_poly
}

pub fn compute_polynomial_deltas<E: PairingEngine>(
    participants: &[PrivateDecryptionContextSimple<E>],
    polynomial: &DensePolynomial<E::Fr>,
) -> HashMap<usize, E::G2Projective> {
    let h_g2 = E::G2Projective::from(participants[0].setup_params.h);
    participants
        .iter()
        .map(|p| {
            let i = p.index;
            let x_i = p.public_decryption_contexts[i].domain;
            let eval = polynomial.evaluate(&x_i);
            let eval_g2 = h_g2.mul(eval.into_repr());
            (i, eval_g2)
        })
        .collect::<HashMap<_, _>>()
}

// TODO: Expose a method to create a proper decryption share after refreshing
pub fn refresh_private_key_share<E: PairingEngine>(
    h: &E::G2Projective,
    domain_point: &E::Fr,
    polynomial: &DensePolynomial<E::Fr>,
    validator_private_key_share: &E::G2Affine,
) -> PrivateKeyShare<E> {
    // let h_g2 = E::G2Projective::from(participant.setup_params.h);
    // let domain_point =
    //     participant.public_decryption_contexts[participant.index].domain;
    let evaluated_polynomial = polynomial.evaluate(domain_point);
    let share_update = h.mul(evaluated_polynomial.into_repr());
    let updated_share =
        validator_private_key_share.into_projective() + share_update;
    PrivateKeyShare {
        private_key_share: updated_share.into_affine(),
    }
}
