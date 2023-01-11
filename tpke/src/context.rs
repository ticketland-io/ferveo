use crate::*;

#[derive(Clone, Debug)]
pub struct PublicDecryptionContextFast<E: PairingEngine> {
    pub domain: Vec<E::Fr>,
    pub public_key_shares: PublicKeyShares<E>,
    pub blinded_key_shares: BlindedKeyShares<E>,
    // This decrypter's contribution to N(0), namely (-1)^|domain| * \prod_i omega_i
    pub lagrange_n_0: E::Fr,
}

#[derive(Clone, Debug)]
pub struct PublicDecryptionContextSimple<E: PairingEngine> {
    pub domain: E::Fr,
    pub public_key_shares: PublicKeyShares<E>,
    pub blinded_key_shares: BlindedKeyShares<E>,
}

#[derive(Clone, Debug)]
pub struct SetupParams<E: PairingEngine> {
    pub b: E::Fr,
    pub b_inv: E::Fr,
    pub g: E::G1Affine,
    pub g_inv: E::G1Prepared,
    pub h_inv: E::G2Prepared,
    pub h: E::G2Affine,
}

#[derive(Clone, Debug)]
pub struct PrivateDecryptionContextFast<E: PairingEngine> {
    pub index: usize,
    pub setup_params: SetupParams<E>,
    pub private_key_share: PrivateKeyShare<E>,
    pub public_decryption_contexts: Vec<PublicDecryptionContextFast<E>>,
    pub scalar_bits: usize,
    pub window_size: usize,
}

#[derive(Clone, Debug)]
pub struct PrivateDecryptionContextSimple<E: PairingEngine> {
    pub index: usize,
    pub setup_params: SetupParams<E>,
    pub private_key_share: PrivateKeyShare<E>,
    pub public_decryption_contexts: Vec<PublicDecryptionContextSimple<E>>,
}
