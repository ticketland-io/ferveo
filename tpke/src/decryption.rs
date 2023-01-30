#![allow(non_snake_case)]

use crate::*;

use itertools::zip_eq;

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
pub fn verify_decryption_shares_fast<E: PairingEngine>(
    pub_contexts: &[PublicDecryptionContextFast<E>],
    ciphertext: &Ciphertext<E>,
    decryption_shares: &[DecryptionShareFast<E>],
) -> bool {
    // [b_i] H
    let blinding_keys = decryption_shares
        .iter()
        .map(|d| {
            pub_contexts[d.decrypter_index]
                .blinded_key_share
                .blinding_key_prepared
                .clone()
        })
        .collect::<Vec<_>>();

    // e(U, -H)
    let pairing_a = (
        E::G1Prepared::from(ciphertext.commitment),
        pub_contexts[0].h_inv.clone(),
    );

    for (d_i, p_i) in zip_eq(decryption_shares, blinding_keys) {
        // e(D_i, B_i)
        let pairing_b = (E::G1Prepared::from(d_i.decryption_share), p_i);
        if E::product_of_pairings(&[pairing_a.clone(), pairing_b.clone()])
            != E::Fqk::one()
        {
            return false;
        }
    }

    true
}

#[derive(Debug, Clone)]
pub struct DecryptionShareSimplePrecomputed<E: PairingEngine> {
    pub decrypter_index: usize,
    pub decryption_share: E::Fqk,
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
