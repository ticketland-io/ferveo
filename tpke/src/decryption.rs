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
