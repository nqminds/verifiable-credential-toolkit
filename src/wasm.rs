use crate::UnsignedVerifiableCredential;
use crate::VerifiableCredential;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn sign(unsigned_vc: JsValue, private_key: &[u8]) -> Result<JsValue, JsError> {
    let unsigned: UnsignedVerifiableCredential = from_value(unsigned_vc).map_err(|e| {
        JsError::new(&format!(
            "Failed to deserialize unsigned verifiable credential: {}",
            e
        ))
    })?;

    let signed = unsigned
        .sign(private_key)
        .map_err(|e| JsError::new(&format!("Signing failed: {}", e)))?;
    Ok(to_value(&signed)?)
}

#[wasm_bindgen]
pub fn verify(signed_vc: JsValue, public_key: &[u8]) -> Result<bool, JsError> {
    let vc: VerifiableCredential = from_value(signed_vc).map_err(|e| {
        JsError::new(&format!(
            "Failed to deserialize signed verifiable credential: {}",
            e
        ))
    })?;
    match vc.verify(public_key) {
        Ok(_) => Ok(true),
        Err(_e) => Ok(false),
    }
}

#[wasm_bindgen]
pub struct KeyPair {
    signing_key: Vec<u8>,
    verifying_key: Vec<u8>,
}

#[wasm_bindgen]
impl KeyPair {
    pub fn new(signing_key: Vec<u8>, verifying_key: Vec<u8>) -> KeyPair {
        KeyPair {
            signing_key,
            verifying_key,
        }
    }

    pub fn signing_key(&self) -> Vec<u8> {
        self.signing_key.clone()
    }

    pub fn verifying_key(&self) -> Vec<u8> {
        self.verifying_key.clone()
    }
}

/// Generate a new keypair
#[wasm_bindgen]
pub fn generate_keypair() -> KeyPair {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let signing_key_bytes = signing_key.to_bytes().to_vec();
    let verifying_key_bytes = verifying_key.to_bytes().to_vec();

    KeyPair::new(signing_key_bytes, verifying_key_bytes)
}
