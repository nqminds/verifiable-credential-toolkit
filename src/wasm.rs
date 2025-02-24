use crate::UnsignedVerifiableCredential;
use crate::VerifiableCredential;
use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn sign(unsigned_vc: JsValue, private_key: &[u8]) -> Result<JsValue, JsError> {
    let unsigned: UnsignedVerifiableCredential = from_value(unsigned_vc)?;
    let signed = unsigned
        .sign(private_key)
        .map_err(|e| JsError::new(&format!("Signing failed: {}", e)))?;
    Ok(to_value(&signed)?)
}

#[wasm_bindgen]
pub fn verify(signed_vc: JsValue, public_key: &[u8]) -> Result<bool, JsError> {
    let vc: VerifiableCredential = from_value(signed_vc)?;
    match vc.verify(public_key) {
        Ok(_) => Ok(true),
        Err(_e) => Ok(false),
    }
}
