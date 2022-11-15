mod serialization;
mod utils;

extern crate group_threshold_cryptography as tpke;

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{BigInteger256, ToBytes};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use utils::set_panic_hook;
use wasm_bindgen::prelude::*;

extern crate alloc;
// Use `wee_alloc` as the global allocator.
extern crate wee_alloc;

pub type E = ark_bls12_381::Bls12_381;
pub type TpkePublicKey = ark_bls12_381::G1Affine;
pub type TpkePrivateKey = ark_bls12_381::G2Affine;
pub type TpkeCiphertext = tpke::Ciphertext<E>;
pub type TpkeDecryptionShare = tpke::DecryptionShare<E>;
pub type TpkePublicDecryptionContext = tpke::PublicDecryptionContext<E>;
pub type TpkeSharedSecret =
    <ark_bls12_381::Bls12_381 as ark_ec::PairingEngine>::Fqk;

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct PrivateDecryptionContext {
    b_inv: ark_bls12_381::Fr,
    decrypter_index: usize,
}

impl PrivateDecryptionContext {
    const B_INV_LEN: usize = 32;
    const DECRYPTER_INDEX_LEN: usize = 8;

    pub(crate) fn new(
        b_inv: ark_bls12_381::Fr,
        decrypter_index: usize,
    ) -> Self {
        Self {
            b_inv,
            decrypter_index,
        }
    }

    pub fn serialized_size() -> usize {
        Self::B_INV_LEN + Self::DECRYPTER_INDEX_LEN
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.b_inv.0.write(&mut bytes).unwrap();

        let decrypter_index =
            bincode::serialize(&self.decrypter_index).unwrap();
        bytes.extend(decrypter_index);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let b_inv_bytes = &bytes[0..Self::B_INV_LEN];
        let b_inv = b_inv_bytes
            .chunks(8)
            .map(|x| {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(x);
                u64::from_le_bytes(bytes)
            })
            .collect::<Vec<u64>>();
        let b_inv: [u64; 4] = b_inv.try_into().unwrap();
        let b_inv = ark_bls12_381::Fr::new(BigInteger256::new(b_inv));

        let decrypter_index_bytes = &bytes
            [Self::B_INV_LEN..Self::B_INV_LEN + Self::DECRYPTER_INDEX_LEN];
        let decrypter_index =
            bincode::deserialize(decrypter_index_bytes).unwrap();

        Self {
            b_inv,
            decrypter_index,
        }
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct DecryptionShare(TpkeDecryptionShare);

#[wasm_bindgen]
impl DecryptionShare {
    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let share = TpkeDecryptionShare::from_bytes(bytes);
        Self(share)
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct ParticipantPayload {
    decryption_context: PrivateDecryptionContext,
    ciphertext: TpkeCiphertext,
}

impl ParticipantPayload {
    pub fn new(
        decryption_context: PrivateDecryptionContext,
        ciphertext: Ciphertext,
    ) -> Self {
        ParticipantPayload {
            decryption_context,
            ciphertext: ciphertext.0,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.decryption_context.to_bytes();
        bytes.extend(&self.ciphertext.to_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let decryption_context_bytes =
            &bytes[0..PrivateDecryptionContext::serialized_size()];
        let decryption_context =
            PrivateDecryptionContext::from_bytes(decryption_context_bytes);

        let ciphertext_bytes =
            bytes[PrivateDecryptionContext::serialized_size()..].to_vec();
        let ciphertext = tpke::Ciphertext::from_bytes(&ciphertext_bytes);

        ParticipantPayload {
            decryption_context,
            ciphertext,
        }
    }

    pub fn to_decryption_share(&self) -> DecryptionShare {
        // TODO: Add verification steps

        let decryption_share = self
            .ciphertext
            .nonce
            .mul(self.decryption_context.b_inv)
            .into_affine();

        DecryptionShare(TpkeDecryptionShare {
            decrypter_index: self.decryption_context.decrypter_index,
            decryption_share,
        })
    }
}

#[serde_as]
#[wasm_bindgen]
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey(
    #[serde_as(as = "serialization::SerdeAs")] pub(crate) TpkePublicKey,
);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut reader = bytes;
        let pk = TpkePublicKey::deserialize_uncompressed(&mut reader).unwrap();
        PublicKey(pk)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.0.serialize_uncompressed(&mut bytes).unwrap();
        bytes
    }
}
#[serde_as]
#[wasm_bindgen]
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct PrivateKey(
    #[serde_as(as = "serialization::SerdeAs")] pub(crate) TpkePrivateKey,
);

impl PrivateKey {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut reader = bytes;
        let pk = TpkePrivateKey::deserialize_uncompressed(&mut reader).unwrap();
        PrivateKey(pk)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.0.serialize_uncompressed(&mut bytes).unwrap();
        bytes
    }
}

#[wasm_bindgen]
pub struct Setup {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
    private_contexts: Vec<PrivateDecryptionContext>,
    public_contexts: Vec<TpkePublicDecryptionContext>,
}

#[wasm_bindgen]
impl Setup {
    #[wasm_bindgen(constructor)]
    pub fn new(
        threshold: usize,
        shares_num: usize,
        num_entities: usize,
    ) -> Self {
        set_panic_hook();

        let (public_key, private_key, contexts) =
            tpke::setup::<E>(threshold, shares_num, num_entities);
        let private_contexts = contexts
            .clone()
            .into_iter()
            .map(|x| PrivateDecryptionContext::new(x.b_inv, x.index))
            .collect();
        let public_contexts = contexts[0].public_decryption_contexts.to_vec();

        Self {
            public_key: PublicKey(public_key),
            private_key: PrivateKey(private_key),
            private_contexts,
            public_contexts,
        }
    }

    // Using `private_context_at` and `decrypter_indexes` instead of making `private_context` public
    // as a workaround for wasm-bindgen not supporting `Vec` with a custom defined types without serde
    // serialization.

    pub fn private_context_at(&self, index: usize) -> PrivateDecryptionContext {
        set_panic_hook();
        let context = self.private_contexts[index].clone();
        assert_eq!(context.decrypter_index, index);
        context
    }

    pub fn decrypter_indexes(&self) -> Vec<usize> {
        set_panic_hook();
        self.private_contexts
            .iter()
            .map(|x| x.decrypter_index)
            .collect()
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct Ciphertext(pub(crate) TpkeCiphertext);

#[wasm_bindgen]
pub fn encrypt(message: Vec<u8>, public_key: PublicKey) -> Ciphertext {
    set_panic_hook();

    let mut rng = rand::thread_rng();
    let ciphertext = tpke::encrypt::<_, E>(&message, public_key.0, &mut rng);
    Ciphertext(ciphertext)
}

#[wasm_bindgen]
pub fn decrypt(ciphertext: Ciphertext, private_key: PrivateKey) -> Vec<u8> {
    set_panic_hook();
    tpke::decrypt(&ciphertext.0, private_key.0)
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct SharedSecret(TpkeSharedSecret);

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct SharedSecretBuilder {
    shares: Vec<TpkeDecryptionShare>,
    contexts: Vec<TpkePublicDecryptionContext>,
}
#[wasm_bindgen]
impl SharedSecretBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(setup: Setup) -> Self {
        SharedSecretBuilder {
            shares: vec![],
            contexts: setup.public_contexts,
        }
    }

    #[wasm_bindgen]
    pub fn add_decryption_share(&mut self, share: DecryptionShare) {
        self.shares.push(share.0);
    }

    #[wasm_bindgen]
    pub fn build(&self) -> SharedSecret {
        set_panic_hook();

        if self.shares.len() != self.contexts.len() {
            panic!("Number of shares and contexts must be equal");
        }

        let prepared_blinded_key_shares =
            tpke::prepare_combine(&self.contexts, &self.shares);
        let shared_secret =
            tpke::share_combine(&self.shares, &prepared_blinded_key_shares);
        SharedSecret(shared_secret)
    }
}

#[wasm_bindgen]
pub fn decrypt_with_shared_secret(
    ciphertext: Ciphertext,
    shared_secret: SharedSecret,
) -> Vec<u8> {
    set_panic_hook();

    tpke::decrypt_with_shared_secret(&ciphertext.0, &shared_secret.0)
}
