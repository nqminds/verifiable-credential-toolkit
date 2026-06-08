use crate::UnsignedVerifiableCredential;
use crate::VerifiableCredential;
use crate::{SchemaSource, SigningKey, VerifyingKey};
use js_sys::{Array, Reflect};
use serde::Serialize;
use serde_wasm_bindgen::from_value;
use wasm_bindgen::prelude::*;

/// Serialize a Rust value to a JsValue using plain JS objects (not Maps).
fn to_js_value<T: Serialize>(value: &T) -> Result<JsValue, serde_wasm_bindgen::Error> {
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    value.serialize(&serializer)
}

// Helper function to normalize a JS object by removing undefined values
#[wasm_bindgen]
pub fn normalize_object(input: &JsValue) -> Result<JsValue, JsError> {
    if input.is_undefined() {
        // Return undefined as is
        return Ok(JsValue::undefined());
    } else if input.is_null() {
        // Return null as is
        return Ok(JsValue::null());
    } else if Array::is_array(input) {
        // Handle array case
        let array = Array::from(input);
        let result = Array::new();

        for i in 0..array.length() {
            let item = array.get(i);

            // Skip undefined items in arrays
            if item.is_undefined() {
                continue;
            }

            // Recursively normalize array items
            let normalized_item = normalize_object(&item)?;
            result.push(&normalized_item);
        }

        return Ok(result.into());
    } else if input.is_object() {
        // Handle regular object case
        let obj = js_sys::Object::from(input.clone());
        let result = js_sys::Object::new();

        // Get all own properties
        let keys = js_sys::Object::keys(&obj);
        let keys_len = keys.length();

        for i in 0..keys_len {
            let key = keys.get(i);

            // Get property value
            let value =
                Reflect::get(&obj, &key).map_err(|_| JsError::new("Failed to get property"))?;

            // Skip undefined values
            if value.is_undefined() {
                continue;
            }

            // Recursively normalize the value
            let normalized_value = normalize_object(&value)?;

            // Set property on result object
            Reflect::set(&result, &key, &normalized_value)
                .map_err(|_| JsError::new("Failed to set property"))?;
        }

        return Ok(result.into());
    }

    // For primitive values, return as is
    Ok(input.clone())
}

// Function to normalize a value and then convert to string for debugging
#[wasm_bindgen]
pub fn normalize_and_stringify(input: &JsValue) -> Result<String, JsError> {
    let normalized = normalize_object(input)?;
    let json = js_sys::JSON::stringify(&normalized)
        .map_err(|_| JsError::new("Failed to stringify normalized object"))?;

    Ok(json.as_string().unwrap_or_default())
}

#[wasm_bindgen]
pub fn sign(unsigned_vc: JsValue, private_key: &[u8]) -> Result<JsValue, JsError> {
    // First convert to JSON and back to ensure we have a clean object
    let json_str = js_sys::JSON::stringify(&unsigned_vc)
        .map_err(|_| JsError::new("Failed to stringify input"))?;
    let clean_obj = js_sys::JSON::parse(
        &json_str
            .as_string()
            .ok_or_else(|| JsError::new("Failed to get string"))?,
    )
    .map_err(|_| JsError::new("Failed to parse JSON"))?;

    // Then normalize to remove undefined values
    let normalized_vc = normalize_object(&clean_obj)?;

    // Process with the normalized value
    let unsigned: UnsignedVerifiableCredential = from_value(normalized_vc).map_err(|e| {
        JsError::new(&format!(
            "Failed to deserialize unsigned verifiable credential: {}",
            e
        ))
    })?;

    let signing_key = SigningKey::from_bytes(private_key)
        .map_err(|e| JsError::new(&format!("Invalid private key: {}", e)))?;
    let signed = unsigned
        .sign(&signing_key)
        .map_err(|e| JsError::new(&format!("Signing failed: {}", e)))?;

    Ok(to_js_value(&signed)?)
}

#[wasm_bindgen]
pub fn verify(signed_vc: JsValue, public_key: &[u8]) -> Result<bool, JsError> {
    let vc: VerifiableCredential = from_value(signed_vc).map_err(|e| {
        JsError::new(&format!(
            "Failed to deserialize signed verifiable credential: {}",
            e
        ))
    })?;

    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return Ok(false);
    };
    match vc.verify(&verifying_key) {
        Ok(_) => Ok(true),
        Err(_e) => Ok(false),
    }
}
#[wasm_bindgen]
pub fn verify_with_schema_check(
    signed_vc: JsValue,
    public_key: &[u8],
    schema: JsValue,
) -> Result<bool, JsError> {
    let vc: VerifiableCredential = from_value(signed_vc).map_err(|e| {
        JsError::new(&format!(
            "Failed to deserialize signed verifiable credential: {}",
            e
        ))
    })?;

    let schema_value = serde_wasm_bindgen::from_value::<serde_json::Value>(schema)
        .map_err(|_| JsError::new("Failed to deserialize schema"))?;
    if vc.validate(&SchemaSource::Inline(&schema_value)).is_err() {
        return Ok(false);
    }
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return Ok(false);
    };
    match vc.verify(&verifying_key) {
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
    let keypair = crate::generate_keypair();
    KeyPair::new(
        keypair.signing_key.to_bytes().to_vec(),
        keypair.verifying_key.to_bytes().to_vec(),
    )
}

// protobuf encoding/decoding functions --------------------------------------------------------

#[wasm_bindgen]
pub fn sign_protobuf_vc(
    unsigned_vc_protobuf: &[u8],
    private_key: &[u8],
) -> Result<Vec<u8>, JsError> {
    let signing_key = SigningKey::from_bytes(private_key)
        .map_err(|e| JsError::new(&format!("Invalid private key: {}", e)))?;
    crate::bindings::protobuf::sign_protobuf_vc(unsigned_vc_protobuf, &signing_key)
        .map_err(|e| JsError::new(&format!("Protobuf signing failed: {}", e)))
}

#[wasm_bindgen]
pub fn verify_protobuf_vc(signed_vc_protobuf: &[u8], public_key: &[u8]) -> Result<bool, JsError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| JsError::new(&format!("Invalid public key: {}", e)))?;
    crate::bindings::protobuf::verify_protobuf_vc(signed_vc_protobuf, &verifying_key)
        .map(|_| true)
        .map_err(|e| JsError::new(&format!("Protobuf verification failed: {}", e)))
}

// cbor encoding/decoding functions --------------------------------------------------------

#[wasm_bindgen]
pub fn sign_cbor_vc(unsigned_vc_cbor: &[u8], private_key: &[u8]) -> Result<Vec<u8>, JsError> {
    let signing_key = SigningKey::from_bytes(private_key)
        .map_err(|e| JsError::new(&format!("Invalid private key: {}", e)))?;
    crate::bindings::cbor::sign_cbor_vc(unsigned_vc_cbor, &signing_key)
        .map_err(|e| JsError::new(&format!("CBOR signing failed: {}", e)))
}

#[wasm_bindgen]
pub fn verify_cbor_vc(signed_vc_cbor: &[u8], public_key: &[u8]) -> Result<bool, JsError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| JsError::new(&format!("Invalid public key: {}", e)))?;
    crate::bindings::cbor::verify_cbor_vc(signed_vc_cbor, &verifying_key)
        .map(|_| true)
        .map_err(|e| JsError::new(&format!("CBOR verification failed: {}", e)))
}
