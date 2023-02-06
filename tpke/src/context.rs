use crate::*;
use ark_ec::ProjectiveCurve;

#[derive(Clone, Debug)]
pub struct PublicDecryptionContextFast<E: PairingEngine> {
    pub domain: E::Fr,
    pub public_key_share: PublicKeyShare<E>,
    pub blinded_key_share: BlindedKeyShare<E>,
    // This decrypter's contribution to N(0), namely (-1)^|domain| * \prod_i omega_i
    pub lagrange_n_0: E::Fr,
    pub h_inv: E::G2Prepared,
}

#[derive(Clone, Debug)]
pub struct PublicDecryptionContextSimple<E: PairingEngine> {
    pub domain: E::Fr,
    pub public_key_share: PublicKeyShare<E>,
    pub blinded_key_share: BlindedKeyShare<E>,
    pub h: E::G2Affine,
    pub validator_public_key: E::G2Projective,
}

#[derive(Clone, Debug)]
pub struct SetupParams<E: PairingEngine> {
    pub b: E::Fr,
    pub b_inv: E::Fr,
    pub g: E::G1Affine,
    pub g_inv: E::G1Prepared,
    pub h: E::G2Affine,
}

#[derive(Clone, Debug)]
pub struct PrivateDecryptionContextFast<E: PairingEngine> {
    pub index: usize,
    pub setup_params: SetupParams<E>,
    pub private_key_share: PrivateKeyShare<E>,
    pub public_decryption_contexts: Vec<PublicDecryptionContextFast<E>>,
    pub scalar_bits: usize,
}

impl<E: PairingEngine> PrivateDecryptionContextFast<E> {
    pub fn create_share(
        &self,
        ciphertext: &Ciphertext<E>,
        aad: &[u8],
        g_inv: &E::G1Prepared,
    ) -> Result<DecryptionShareFast<E>> {
        check_ciphertext_validity::<E>(ciphertext, aad, g_inv)?;

        let decryption_share = ciphertext
            .commitment
            .mul(self.setup_params.b_inv)
            .into_affine();

        Ok(DecryptionShareFast {
            decrypter_index: self.index,
            decryption_share,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PrivateDecryptionContextSimple<E: PairingEngine> {
    pub index: usize,
    pub setup_params: SetupParams<E>,
    pub private_key_share: PrivateKeyShare<E>,
    pub public_decryption_contexts: Vec<PublicDecryptionContextSimple<E>>,
    // TODO: Remove/replace with `setup_params.b` after refactoring
    pub validator_private_key: E::Fr,
}

impl<E: PairingEngine> PrivateDecryptionContextSimple<E> {
    // TODO: Rename to checked_create_share? Or get rid of this "checked_ notation"?
    pub fn create_share(
        &self,
        ciphertext: &Ciphertext<E>,
        aad: &[u8],
    ) -> Result<DecryptionShareSimple<E>> {
        DecryptionShareSimple::create(
            self.index,
            &self.validator_private_key,
            &self.private_key_share,
            ciphertext,
            aad,
            &self.setup_params.g_inv,
        )
    }

    pub fn create_share_precomputed(
        &self,
        ciphertext: &Ciphertext<E>,
        lagrange_coeff: &E::Fr,
    ) -> DecryptionShareSimplePrecomputed<E> {
        let u = ciphertext.commitment;
        // U_{λ_i} = [λ_{i}(0)] U
        let u_to_lagrange_coeff = u.mul(lagrange_coeff.into_repr());
        let z_i = self.private_key_share.private_key_share;
        // C_{λ_i} = e(U_{λ_i}, Z_i)
        let c_i = E::pairing(u_to_lagrange_coeff, z_i);

        DecryptionShareSimplePrecomputed {
            decrypter_index: self.index,
            decryption_share: c_i,
        }
    }
}
