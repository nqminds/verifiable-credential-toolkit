use crate::bindings::{
    sign_via, sign_with_algorithm_via, verify_auto_via, verify_via, verify_with_algorithm_via,
    CredentialCodec,
};
use crate::proto_schemas::vc::UnsignedVerifiableCredential as ProtobufUnsignedVerifiableCredential;
use crate::proto_schemas::vc::VerifiableCredential as ProtobufVerifiableCredential;
use crate::UnsignedVerifiableCredential;
use crate::VerifiableCredential;
use crate::{Algorithm, SigningKey, VcError, VerifyingKey};
use protobuf::Message;
use protobuf_json_mapping::{
    parse_from_str as json_to_protobuf, print_to_string as protobuf_to_json,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

pub type ProtoResult<T> = Result<T, Box<dyn std::error::Error>>;

/// `json_name` of every field whose JSON shape is open (arbitrary objects or
/// string-or-object polymorphism). On the wire these are typed `string` fields holding
/// the field's exact JSON text. They cannot be `google.protobuf.Value`: that type's only
/// numeric kind is an IEEE-754 double, so it turns every integer into a float and rounds
/// integers beyond 2^53. Carrying the JSON text instead makes the round-trip lossless.
const DYNAMIC_JSON_FIELDS: &[&str] = &[
    "name",
    "description",
    "issuer",
    "credentialSubject",
    "holder",
];

/// The Protobuf serialization format.
///
/// The wire schema (`vc.proto`) is typed, but the bridge between Rust and protobuf
/// still goes through the protobuf<->JSON canonical mapping: protobuf cannot natively
/// represent the dynamic-object fields (`credentialSubject`, polymorphic `issuer`,
/// etc.), so those are carried as their exact JSON text in `string` fields, stringified
/// on encode and parsed back on decode. Everything then round-trips losslessly.
pub struct Protobuf;

/// Wrap a format-specific error in [VcError::Codec].
fn codec_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> VcError {
    VcError::Codec(Box::new(e))
}

impl CredentialCodec for Protobuf {
    fn decode_unsigned(bytes: &[u8]) -> Result<UnsignedVerifiableCredential, VcError> {
        decode_from_protobuf::<ProtobufUnsignedVerifiableCredential, _>(bytes)
    }

    fn decode_signed(bytes: &[u8]) -> Result<VerifiableCredential, VcError> {
        decode_from_protobuf::<ProtobufVerifiableCredential, _>(bytes)
    }

    fn encode_signed(vc: &VerifiableCredential) -> Result<Vec<u8>, VcError> {
        encode_to_protobuf::<_, ProtobufVerifiableCredential>(vc)
    }
}

/// Decode protobuf bytes of message `M` into the Rust domain type `T`, routing through
/// the protobuf<->JSON mapping and parsing the dynamic JSON-text fields back into values.
fn decode_from_protobuf<M, T>(bytes: &[u8]) -> Result<T, VcError>
where
    M: protobuf::MessageFull,
    T: DeserializeOwned,
{
    let protobuf = M::parse_from_bytes(bytes).map_err(codec_err)?;
    let json = protobuf_to_json(&protobuf).map_err(codec_err)?;
    let mut value: Value = serde_json::from_str(&json)?;
    denormalize_from_protobuf(&mut value);
    Ok(serde_json::from_value(value)?)
}

/// Wrap a bare value in a single-element array, leaving existing arrays untouched.
///
/// Rust's `OneOrMany` serializes a single-element list as a scalar, but protobuf's
/// canonical JSON mapping requires arrays for `repeated` fields. This bridges the gap.
fn coerce_to_array(slot: Option<&mut Value>) {
    if let Some(v) = slot {
        if !v.is_array() && !v.is_null() {
            *v = Value::Array(vec![v.take()]);
        }
    }
}

/// Reconcile a credential's serde JSON with what protobuf's canonical JSON mapping
/// expects, before encoding.
///
/// Two mismatches are handled:
/// - serde's `OneOrMany` emits a single-element list as a scalar, but `repeated`
///   protobuf fields require arrays. Field paths here must match the `repeated`
///   fields in `vc.proto`.
/// - serde emits the credential's optional top-level `id` as an explicit `null` when
///   absent (it has no `skip_serializing_if`), but protobuf rejects `null` for a
///   scalar `string`. Dropping top-level `null` keys maps "absent" to "unset". Only
///   typed scalar/message fields live at the top level, so the dynamic `Value` fields
///   (which may legitimately carry `null`) are never recursed into here.
fn normalize_for_protobuf(value: &mut Value) {
    let Some(obj) = value.as_object_mut() else {
        return;
    };

    obj.retain(|_, v| !v.is_null());

    // Top-level OneOrMany fields.
    coerce_to_array(obj.get_mut("type"));
    coerce_to_array(obj.get_mut("credentialSchema"));

    if let Some(status) = obj
        .get_mut("credentialStatus")
        .and_then(Value::as_object_mut)
    {
        coerce_to_array(status.get_mut("type"));
    }

    if let Some(proof) = obj.get_mut("proof").and_then(Value::as_object_mut) {
        coerce_to_array(proof.get_mut("domain"));
        coerce_to_array(proof.get_mut("nonce"));
    }

    // Dynamic JSON fields are carried on the wire as their exact JSON text, so the
    // typed `string` field is lossless where `google.protobuf.Value` was not.
    for field in DYNAMIC_JSON_FIELDS {
        if let Some(v) = obj.get_mut(*field) {
            if !v.is_null() {
                let text = serde_json::to_string(v).expect("serde_json::Value re-serializes");
                *v = Value::String(text);
            }
        }
    }
}

/// Inverse of the dynamic-field stringification in [normalize_for_protobuf]: parse each
/// JSON-text `string` field back into the JSON value it encodes, after decoding.
fn denormalize_from_protobuf(value: &mut Value) {
    let Some(obj) = value.as_object_mut() else {
        return;
    };

    for field in DYNAMIC_JSON_FIELDS {
        let parsed = match obj.get(*field) {
            Some(Value::String(text)) => serde_json::from_str::<Value>(text).ok(),
            _ => None,
        };
        if let Some(parsed) = parsed {
            obj.insert((*field).to_string(), parsed);
        }
    }
}

/// Serialize a Rust credential type into protobuf bytes for message `M`, routing
/// through the normalized protobuf<->JSON mapping.
fn encode_to_protobuf<S, M>(value: &S) -> Result<Vec<u8>, VcError>
where
    S: Serialize,
    M: protobuf::MessageFull,
{
    let mut json = serde_json::to_value(value)?;
    normalize_for_protobuf(&mut json);
    let protobuf: M = json_to_protobuf(&serde_json::to_string(&json)?).map_err(codec_err)?;
    protobuf.write_to_bytes().map_err(codec_err)
}

/// Decode protobuf bytes into the protobuf-generated unsigned VC struct.
pub fn decode_unsigned_vc_from_protobuf(
    bytes: &[u8],
) -> ProtoResult<ProtobufUnsignedVerifiableCredential> {
    Ok(ProtobufUnsignedVerifiableCredential::parse_from_bytes(
        bytes,
    )?)
}

/// Decode protobuf bytes into the protobuf-generated signed VC struct.
pub fn decode_signed_vc_from_protobuf(bytes: &[u8]) -> ProtoResult<ProtobufVerifiableCredential> {
    Ok(ProtobufVerifiableCredential::parse_from_bytes(bytes)?)
}

/// Encode an unsigned VC Rust struct into protobuf bytes.
pub fn encode_unsigned_vc_to_protobuf(vc: &UnsignedVerifiableCredential) -> ProtoResult<Vec<u8>> {
    Ok(encode_to_protobuf::<_, ProtobufUnsignedVerifiableCredential>(vc)?)
}

/// Encode the existing signed VC Rust struct into protobuf bytes.
pub fn encode_signed_vc_to_protobuf(vc: &VerifiableCredential) -> ProtoResult<Vec<u8>> {
    Ok(encode_to_protobuf::<_, ProtobufVerifiableCredential>(vc)?)
}

/// Convenience wrapper: decode unsigned VC protobuf, sign it, and re-encode as protobuf.
pub fn sign_protobuf_vc(
    unsigned_vc_protobuf: &[u8],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, VcError> {
    sign_via::<Protobuf>(unsigned_vc_protobuf, signing_key)
}

/// Convenience wrapper: decode signed VC protobuf and verify its signature.
pub fn verify_protobuf_vc(
    signed_vc_protobuf: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<(), VcError> {
    verify_via::<Protobuf>(signed_vc_protobuf, verifying_key)
}

/// Decode unsigned VC protobuf, sign with the given [Algorithm] + raw private key,
/// re-encode as protobuf. Supports every cryptosuite (Ed25519, ML-DSA-44/65/87).
pub fn sign_protobuf_vc_with_algorithm(
    unsigned_vc_protobuf: &[u8],
    algorithm: Algorithm,
    private_key: &[u8],
) -> Result<Vec<u8>, VcError> {
    sign_with_algorithm_via::<Protobuf>(unsigned_vc_protobuf, algorithm, private_key)
}

/// Decode signed VC protobuf and verify with an explicit [Algorithm] + raw public key.
pub fn verify_protobuf_vc_with_algorithm(
    signed_vc_protobuf: &[u8],
    algorithm: Algorithm,
    public_key: &[u8],
) -> Result<(), VcError> {
    verify_with_algorithm_via::<Protobuf>(signed_vc_protobuf, algorithm, public_key)
}

/// Decode signed VC protobuf and verify, reading the algorithm from the proof's
/// `cryptosuite`. The caller supplies only the raw public key bytes.
pub fn verify_protobuf_vc_auto(
    signed_vc_protobuf: &[u8],
    public_key: &[u8],
) -> Result<(), VcError> {
    verify_auto_via::<Protobuf>(signed_vc_protobuf, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keypair;
    use serde_json::json;

    fn sample_unsigned_vc() -> UnsignedVerifiableCredential {
        serde_json::from_value(json!({
          "@context": ["https://www.w3.org/ns/credentials/v2"],
          "id": "urn:uuid:9a3e3c0e-2db0-412a-95c7-cf5520ba78df",
          "type": ["VerifiableCredential", "ExampleVerifiableCredential"],
          "issuer": "https://www.example.com/",
          "validFrom": "2024-08-22T13:53:32.295644150Z",
          "credentialSchema": {
            "id": "https://www.example.com/foo.json",
            "type": "JsonSchema"
          },
          "credentialSubject": {
            "name": "HenryTrustPhone",
            "id": "HenryTrustPhone-id"
          }
        }
        ))
        .expect("sample unsigned VC should deserialize")
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let keypair = generate_keypair();

        let unsigned_vc = sample_unsigned_vc();
        let unsigned_bytes =
            encode_unsigned_vc_to_protobuf(&unsigned_vc).expect("unsigned encode failed");

        let signed_bytes = sign_protobuf_vc(&unsigned_bytes, &keypair.signing_key)
            .expect("protobuf signing failed");

        verify_protobuf_vc(&signed_bytes, &keypair.verifying_key)
            .expect("protobuf verification failed");
    }

    /// A single-element `type` and a single `credentialSchema` object must still
    /// round-trip: serde emits them as scalars, and the codec must coerce them to
    /// arrays for the typed `repeated` protobuf fields.
    #[test]
    fn test_single_element_oneormany_roundtrip() {
        let keypair = generate_keypair();

        let unsigned_vc: UnsignedVerifiableCredential = serde_json::from_value(json!({
          "@context": ["https://www.w3.org/ns/credentials/v2"],
          "type": "VerifiableCredential",
          "issuer": "https://www.example.com/",
          "credentialSchema": { "id": "https://www.example.com/foo.json", "type": "JsonSchema" },
          "credentialSubject": { "id": "subject-id" }
        }))
        .expect("sample unsigned VC should deserialize");

        let unsigned_bytes =
            encode_unsigned_vc_to_protobuf(&unsigned_vc).expect("unsigned encode failed");
        let signed_bytes = sign_protobuf_vc(&unsigned_bytes, &keypair.signing_key)
            .expect("protobuf signing failed");

        verify_protobuf_vc(&signed_bytes, &keypair.verifying_key)
            .expect("protobuf verification failed");

        // The decoded credential must preserve the single-element shapes.
        let decoded = Protobuf::decode_signed(&signed_bytes).expect("decode failed");
        assert_eq!(
            decoded.unsigned.credential_type,
            vec!["VerifiableCredential"]
        );
        assert_eq!(
            decoded
                .unsigned
                .credential_schema
                .as_deref()
                .map(<[_]>::len),
            Some(1)
        );
    }
}
