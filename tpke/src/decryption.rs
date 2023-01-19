#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::*;
use ark_ec::ProjectiveCurve;

#[derive(Debug, Clone)]
pub struct DecryptionShareFast<E: PairingEngine> {
    pub decrypter_index: usize,
    pub decryption_share: E::G1Affine,
}

impl<E: PairingEngine> DecryptionShareFast<E> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let decrypter_index =
            bincode::serialize(&self.decrypter_index).unwrap();
        bytes.extend(&decrypter_index);
        CanonicalSerialize::serialize(&self.decryption_share, &mut bytes)
            .unwrap();

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let INDEX_BYTE_LEN = 8;
        let decrypter_index =
            bincode::deserialize(&bytes[0..INDEX_BYTE_LEN]).unwrap();
        let decryption_share =
            CanonicalDeserialize::deserialize(&bytes[INDEX_BYTE_LEN..])
                .unwrap();

        DecryptionShareFast {
            decrypter_index,
            decryption_share,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecryptionShareSimple<E: PairingEngine> {
    pub decrypter_index: usize,
    pub decryption_share: E::Fqk,
}

// TODO: Benchmark this
pub fn batch_verify_decryption_shares<R: RngCore, E: PairingEngine>(
    pub_contexts: &[PublicDecryptionContextFast<E>],
    ciphertexts: &[Ciphertext<E>],
    decryption_shares: &[Vec<DecryptionShareFast<E>>],
    rng: &mut R,
) -> bool {
    let num_ciphertexts = ciphertexts.len();
    let num_shares = decryption_shares[0].len();

    // Get [b_i] H for each of the decryption shares
    let blinding_keys = decryption_shares[0]
        .iter()
        .map(|d| {
            pub_contexts[d.decrypter_index]
                .blinded_key_share
                .blinding_key_prepared
                .clone()
        })
        .collect::<Vec<_>>();

    // For each ciphertext, generate num_shares random scalars
    let alpha_ij = (0..num_ciphertexts)
        .map(|_| generate_random::<_, E>(num_shares, rng))
        .collect::<Vec<_>>();

    let mut pairings = Vec::with_capacity(num_shares + 1);

    // Compute \sum_i \alpha_{i,j} for each ciphertext j
    let sum_alpha_i = alpha_ij
        .iter()
        .map(|alpha_j| alpha_j.iter().sum::<E::Fr>())
        .collect::<Vec<_>>();

    // Compute \sum_j [ \sum_i \alpha_{i,j} ] U_j
    let sum_u_j = E::G1Prepared::from(
        izip!(ciphertexts.iter(), sum_alpha_i.iter())
            .map(|(c, alpha_j)| c.commitment.mul(*alpha_j))
            .sum::<E::G1Projective>()
            .into_affine(),
    );

    // e(\sum_j [ \sum_i \alpha_{i,j} ] U_j, -H)
    pairings.push((sum_u_j, pub_contexts[0].h_inv.clone()));

    let mut sum_d_j = vec![E::G1Projective::zero(); num_shares];

    // sum_D_j = { [\sum_j \alpha_{i,j} ] D_i }
    for (d, alpha_j) in izip!(decryption_shares.iter(), alpha_ij.iter()) {
        for (sum_alpha_d_i, d_ij, alpha) in
            izip!(sum_d_j.iter_mut(), d.iter(), alpha_j.iter())
        {
            *sum_alpha_d_i += d_ij.decryption_share.mul(*alpha);
        }
    }

    // e([\sum_j \alpha_{i,j} ] D_i, B_i)
    for (d_i, b_i) in izip!(sum_d_j.iter(), blinding_keys.iter()) {
        pairings.push((E::G1Prepared::from(d_i.into_affine()), b_i.clone()));
    }

    E::product_of_pairings(&pairings) == E::Fqk::one()
}

#[cfg(test)]
mod tests {
    use crate::*;

    type E = ark_bls12_381::Bls12_381;

    #[test]
    fn decryption_share_serialization() {
        let decryption_share = DecryptionShareFast::<E> {
            decrypter_index: 1,
            decryption_share: ark_bls12_381::G1Affine::prime_subgroup_generator(
            ),
        };

        let serialized = decryption_share.to_bytes();
        let deserialized: DecryptionShareFast<E> =
            DecryptionShareFast::from_bytes(&serialized);
        assert_eq!(serialized, deserialized.to_bytes())
    }
}
