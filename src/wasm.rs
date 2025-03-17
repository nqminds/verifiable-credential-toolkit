use crate::UnsignedVerifiableCredential;
use crate::VerifiableCredential;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde_json::{Map, Value};
use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::prelude::*;

// Helper function to normalize a JsValue by removing undefined values
fn normalize_js_value(js_value: &JsValue) -> Result<JsValue, JsError> {
    // Convert JsValue to serde_json::Value for easier manipulation
    let value_str = js_sys::JSON::stringify(js_value)
        .map_err(|_| JsError::new("Failed to stringify JsValue"))?;
    let value_str = value_str
        .as_string()
        .ok_or_else(|| JsError::new("Failed to get string from JsValue"))?;

    // Parse string to serde_json::Value
    let mut json_value: Value = serde_json::from_str(&value_str)
        .map_err(|e| JsError::new(&format!("Failed to parse JSON: {}", e)))?;

    // Normalize the JSON value (remove null values which were undefined in JS)
    normalize_json_value(&mut json_value);

    // Convert back to JsValue
    let normalized_str = serde_json::to_string(&json_value)
        .map_err(|e| JsError::new(&format!("Failed to serialize JSON: {}", e)))?;

    let normalized_js = js_sys::JSON::parse(&normalized_str)
        .map_err(|_| JsError::new("Failed to parse normalized JSON"))?;

    Ok(normalized_js.into())
}

// Recursively normalize a serde_json::Value by removing null values
fn normalize_json_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            // Collect keys to remove (can't remove while iterating)
            let keys_to_remove: Vec<String> = map
                .iter()
                .filter(|(_, v)| v.is_null())
                .map(|(k, _)| k.clone())
                .collect();

            // Remove null values
            for key in keys_to_remove {
                map.remove(&key);
            }

            // Recursively normalize nested objects
            for (_, v) in map.iter_mut() {
                normalize_json_value(v);
            }
        }
        Value::Array(arr) => {
            // Recursively normalize array elements
            for item in arr.iter_mut() {
                normalize_json_value(item);
            }
        }
        _ => {}
    }
}

#[wasm_bindgen]
pub fn sign(unsigned_vc: JsValue, private_key: &[u8]) -> Result<JsValue, JsError> {
    // Normalize the unsigned VC by removing undefined values
    let normalized_vc = normalize_js_value(&unsigned_vc)?;

    // Process with the normalized value
    let unsigned: UnsignedVerifiableCredential = from_value(normalized_vc).map_err(|e| {
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
    // Also normalize during verification for consistency
    let normalized_vc = normalize_js_value(&signed_vc)?;

    let vc: VerifiableCredential = from_value(normalized_vc).map_err(|e| {
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
