use crate::bindings::{cbor::Cbor, protobuf::Protobuf, CredentialCodec};
use crate::UnsignedVerifiableCredential;
use crate::VerifiableCredential;
use crate::{generate_keypair_bytes, Algorithm, SchemaSource, SigningKey, VerifyingKey};
use js_sys::{Array, Reflect};
use serde::Serialize;
use serde_wasm_bindgen::from_value;
use wasm_bindgen::prelude::*;

/// Serialize a Rust value to a JsValue using plain JS objects (not Maps).
fn to_js_value<T: Serialize>(value: &T) -> Result<JsValue, serde_wasm_bindgen::Error> {
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    value.serialize(&serializer)
}

/// Round-trip a JS value through `JSON.stringify`/`parse` and strip `undefined`s,
/// yielding a clean object ready to deserialize into a Rust domain type.
fn clean_js_value(input: &JsValue) -> Result<JsValue, JsError> {
    let json_str =
        js_sys::JSON::stringify(input).map_err(|_| JsError::new("Failed to stringify input"))?;
    let clean_obj = js_sys::JSON::parse(
        &json_str
            .as_string()
            .ok_or_else(|| JsError::new("Failed to get string"))?,
    )
    .map_err(|_| JsError::new("Failed to parse JSON"))?;
    normalize_object(&clean_obj)
}

/// Deserialize a JS object into an [UnsignedVerifiableCredential].
fn unsigned_vc_from_js(input: &JsValue) -> Result<UnsignedVerifiableCredential, JsError> {
    from_value(clean_js_value(input)?).map_err(|e| {
        JsError::new(&format!(
            "Failed to deserialize unsigned verifiable credential: {e}"
        ))
    })
}

/// Deserialize a JS object into a [VerifiableCredential].
fn signed_vc_from_js(input: &JsValue) -> Result<VerifiableCredential, JsError> {
    from_value(clean_js_value(input)?).map_err(|e| {
        JsError::new(&format!(
            "Failed to deserialize signed verifiable credential: {e}"
        ))
    })
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
    let unsigned = unsigned_vc_from_js(&unsigned_vc)?;

    let signing_key = SigningKey::new(Algorithm::Ed25519, private_key)
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

    let Ok(verifying_key) = VerifyingKey::new(Algorithm::Ed25519, public_key) else {
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
    let Ok(verifying_key) = VerifyingKey::new(Algorithm::Ed25519, public_key) else {
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

/// Generate a new Ed25519 keypair
#[wasm_bindgen]
pub fn generate_keypair() -> KeyPair {
    let (signing_key, verifying_key) = generate_keypair_bytes(Algorithm::Ed25519);
    KeyPair::new(signing_key, verifying_key)
}

/// Parse an algorithm label ("Ed25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87";
/// case- and separator-insensitive) into an [Algorithm].
fn parse_algorithm(label: &str) -> Result<Algorithm, JsError> {
    match label
        .to_ascii_lowercase()
        .replace(['-', '_', ' '], "")
        .as_str()
    {
        "ed25519" => Ok(Algorithm::Ed25519),
        "mldsa44" => Ok(Algorithm::MlDsa44),
        "mldsa65" => Ok(Algorithm::MlDsa65),
        "mldsa87" => Ok(Algorithm::MlDsa87),
        _ => Err(JsError::new(&format!("unknown algorithm: {label}"))),
    }
}

/// Generate a key pair for the given algorithm label, returning raw key bytes
/// (Ed25519 or ML-DSA-44/65/87 in their FIPS 204 encodings).
#[wasm_bindgen]
pub fn generate_keypair_for(algorithm: &str) -> Result<KeyPair, JsError> {
    let (private_key, public_key) = generate_keypair_bytes(parse_algorithm(algorithm)?);
    Ok(KeyPair::new(private_key, public_key))
}

/// Sign an unsigned credential (JS object) with the given algorithm and a raw private key
/// of the matching length (Ed25519: 32 bytes; ML-DSA: the FIPS 204 expanded signing key).
#[wasm_bindgen]
pub fn sign_with_algorithm(
    unsigned_vc: JsValue,
    algorithm: &str,
    private_key: &[u8],
) -> Result<JsValue, JsError> {
    let unsigned = unsigned_vc_from_js(&unsigned_vc)?;
    let signed = unsigned
        .sign_with_algorithm(parse_algorithm(algorithm)?, private_key)
        .map_err(|e| JsError::new(&format!("Signing failed: {e}")))?;
    Ok(to_js_value(&signed)?)
}

/// Verify a signed credential (JS object) with an explicit algorithm and a raw public key.
/// Returns false on any failure.
#[wasm_bindgen]
pub fn verify_with_algorithm(
    signed_vc: JsValue,
    algorithm: &str,
    public_key: &[u8],
) -> Result<bool, JsError> {
    let vc: VerifiableCredential = from_value(signed_vc).map_err(|e| {
        JsError::new(&format!(
            "Failed to deserialize signed verifiable credential: {e}"
        ))
    })?;
    Ok(vc
        .verify_with_algorithm(parse_algorithm(algorithm)?, public_key)
        .is_ok())
}

/// Verify a signed credential (JS object), reading the algorithm from the proof's
/// `cryptosuite`. The caller supplies only the raw public key bytes. Returns false on any
/// failure (including an unsupported cryptosuite).
#[wasm_bindgen]
pub fn verify_auto(signed_vc: JsValue, public_key: &[u8]) -> Result<bool, JsError> {
    let vc: VerifiableCredential = from_value(signed_vc).map_err(|e| {
        JsError::new(&format!(
            "Failed to deserialize signed verifiable credential: {e}"
        ))
    })?;
    Ok(vc.verify_auto(public_key).is_ok())
}

// protobuf encoding/decoding functions --------------------------------------------------------

/// Encode an unsigned credential (JS object) to Protobuf bytes.
#[wasm_bindgen]
pub fn encode_unsigned_vc_to_protobuf(unsigned_vc: JsValue) -> Result<Vec<u8>, JsError> {
    let unsigned = unsigned_vc_from_js(&unsigned_vc)?;
    Protobuf::encode_unsigned(&unsigned)
        .map_err(|e| JsError::new(&format!("Protobuf encoding failed: {e}")))
}

/// Encode a signed credential (JS object) to Protobuf bytes.
#[wasm_bindgen]
pub fn encode_signed_vc_to_protobuf(signed_vc: JsValue) -> Result<Vec<u8>, JsError> {
    let signed = signed_vc_from_js(&signed_vc)?;
    Protobuf::encode_signed(&signed)
        .map_err(|e| JsError::new(&format!("Protobuf encoding failed: {e}")))
}

/// Decode Protobuf bytes into an unsigned credential (JS object).
#[wasm_bindgen]
pub fn decode_unsigned_vc_from_protobuf(unsigned_vc_protobuf: &[u8]) -> Result<JsValue, JsError> {
    let unsigned = Protobuf::decode_unsigned(unsigned_vc_protobuf)
        .map_err(|e| JsError::new(&format!("Protobuf decoding failed: {e}")))?;
    Ok(to_js_value(&unsigned)?)
}

/// Decode Protobuf bytes into a signed credential (JS object).
#[wasm_bindgen]
pub fn decode_signed_vc_from_protobuf(signed_vc_protobuf: &[u8]) -> Result<JsValue, JsError> {
    let signed = Protobuf::decode_signed(signed_vc_protobuf)
        .map_err(|e| JsError::new(&format!("Protobuf decoding failed: {e}")))?;
    Ok(to_js_value(&signed)?)
}

#[wasm_bindgen]
pub fn sign_protobuf_vc(
    unsigned_vc_protobuf: &[u8],
    private_key: &[u8],
) -> Result<Vec<u8>, JsError> {
    Protobuf::sign(unsigned_vc_protobuf, Algorithm::Ed25519, private_key)
        .map_err(|e| JsError::new(&format!("Protobuf signing failed: {e}")))
}

#[wasm_bindgen]
pub fn verify_protobuf_vc(signed_vc_protobuf: &[u8], public_key: &[u8]) -> Result<bool, JsError> {
    Protobuf::verify(signed_vc_protobuf, Algorithm::Ed25519, public_key)
        .map(|_| true)
        .map_err(|e| JsError::new(&format!("Protobuf verification failed: {e}")))
}

// cbor encoding/decoding functions --------------------------------------------------------

/// Encode an unsigned credential (JS object) to CBOR bytes.
#[wasm_bindgen]
pub fn encode_unsigned_vc_to_cbor(unsigned_vc: JsValue) -> Result<Vec<u8>, JsError> {
    let unsigned = unsigned_vc_from_js(&unsigned_vc)?;
    Cbor::encode_unsigned(&unsigned)
        .map_err(|e| JsError::new(&format!("CBOR encoding failed: {e}")))
}

/// Encode a signed credential (JS object) to CBOR bytes.
#[wasm_bindgen]
pub fn encode_signed_vc_to_cbor(signed_vc: JsValue) -> Result<Vec<u8>, JsError> {
    let signed = signed_vc_from_js(&signed_vc)?;
    Cbor::encode_signed(&signed).map_err(|e| JsError::new(&format!("CBOR encoding failed: {e}")))
}

/// Decode CBOR bytes into an unsigned credential (JS object).
#[wasm_bindgen]
pub fn decode_unsigned_vc_from_cbor(unsigned_vc_cbor: &[u8]) -> Result<JsValue, JsError> {
    let unsigned = Cbor::decode_unsigned(unsigned_vc_cbor)
        .map_err(|e| JsError::new(&format!("CBOR decoding failed: {e}")))?;
    Ok(to_js_value(&unsigned)?)
}

/// Decode CBOR bytes into a signed credential (JS object).
#[wasm_bindgen]
pub fn decode_signed_vc_from_cbor(signed_vc_cbor: &[u8]) -> Result<JsValue, JsError> {
    let signed = Cbor::decode_signed(signed_vc_cbor)
        .map_err(|e| JsError::new(&format!("CBOR decoding failed: {e}")))?;
    Ok(to_js_value(&signed)?)
}

#[wasm_bindgen]
pub fn sign_cbor_vc(unsigned_vc_cbor: &[u8], private_key: &[u8]) -> Result<Vec<u8>, JsError> {
    Cbor::sign(unsigned_vc_cbor, Algorithm::Ed25519, private_key)
        .map_err(|e| JsError::new(&format!("CBOR signing failed: {e}")))
}

#[wasm_bindgen]
pub fn verify_cbor_vc(signed_vc_cbor: &[u8], public_key: &[u8]) -> Result<bool, JsError> {
    Cbor::verify(signed_vc_cbor, Algorithm::Ed25519, public_key)
        .map(|_| true)
        .map_err(|e| JsError::new(&format!("CBOR verification failed: {e}")))
}

// multi-algorithm codec functions ------------------------------------------------------

/// Sign an unsigned CBOR credential with the given algorithm label and raw private key.
#[wasm_bindgen]
pub fn sign_cbor_vc_with_algorithm(
    unsigned_vc_cbor: &[u8],
    algorithm: &str,
    private_key: &[u8],
) -> Result<Vec<u8>, JsError> {
    Cbor::sign(unsigned_vc_cbor, parse_algorithm(algorithm)?, private_key)
        .map_err(|e| JsError::new(&format!("CBOR signing failed: {e}")))
}

/// Verify a signed CBOR credential, reading the algorithm from the proof's `cryptosuite`.
#[wasm_bindgen]
pub fn verify_cbor_vc_auto(signed_vc_cbor: &[u8], public_key: &[u8]) -> Result<bool, JsError> {
    Ok(Cbor::verify_auto(signed_vc_cbor, public_key).is_ok())
}

/// Sign an unsigned Protobuf credential with the given algorithm label and raw private key.
#[wasm_bindgen]
pub fn sign_protobuf_vc_with_algorithm(
    unsigned_vc_protobuf: &[u8],
    algorithm: &str,
    private_key: &[u8],
) -> Result<Vec<u8>, JsError> {
    Protobuf::sign(
        unsigned_vc_protobuf,
        parse_algorithm(algorithm)?,
        private_key,
    )
    .map_err(|e| JsError::new(&format!("Protobuf signing failed: {e}")))
}

/// Verify a signed Protobuf credential, reading the algorithm from the proof's `cryptosuite`.
#[wasm_bindgen]
pub fn verify_protobuf_vc_auto(
    signed_vc_protobuf: &[u8],
    public_key: &[u8],
) -> Result<bool, JsError> {
    Ok(Protobuf::verify_auto(signed_vc_protobuf, public_key).is_ok())
}
