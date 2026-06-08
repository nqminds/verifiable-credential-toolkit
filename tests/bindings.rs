#![cfg(not(target_arch = "wasm32"))]

use c2pa_cbor::to_vec;
use protobuf::Message;
use verifiable_credential_toolkit::{
    bindings::{
        cbor::{
            decode_signed_vc_from_cbor, decode_unsigned_vc_from_cbor, encode_signed_vc_to_cbor,
            sign_cbor_vc, verify_cbor_vc,
        },
        protobuf::{
            decode_signed_vc_from_protobuf, decode_unsigned_vc_from_protobuf,
            encode_signed_vc_to_protobuf, sign_protobuf_vc, verify_protobuf_vc,
        },
    },
    proto_schemas::vc::UnsignedVerifiableCredential as ProtobufUnsignedVerifiableCredential,
    SigningKey, UnsignedVerifiableCredential, VerifiableCredential, VerifyingKey,
};

fn load_private_key() -> SigningKey {
    SigningKey::from_bytes(
        &std::fs::read("tests/test_data/keys/key.priv")
            .expect("Error reading private key from file"),
    )
    .expect("Invalid private key")
}

fn load_public_key() -> VerifyingKey {
    VerifyingKey::from_bytes(
        &std::fs::read("tests/test_data/keys/key.pub").expect("Error reading public key from file"),
    )
    .expect("Invalid public key")
}

fn sample_unsigned_vc() -> UnsignedVerifiableCredential {
    serde_json::from_str(include_str!(
        "test_data/verifiable_credentials/unsigned.json"
    ))
    .expect("Failed to deserialize JSON")
}

fn sample_signed_vc(private_key: &SigningKey) -> VerifiableCredential {
    sample_unsigned_vc()
        .sign(private_key)
        .expect("Failed to sign VC")
}

fn unsigned_vc_to_protobuf_bytes(vc: &UnsignedVerifiableCredential) -> Vec<u8> {
    let json = serde_json::to_string(vc).expect("Failed to serialize VC to JSON");
    let protobuf: ProtobufUnsignedVerifiableCredential =
        protobuf_json_mapping::parse_from_str(&json)
            .expect("Failed to convert JSON to protobuf struct");

    protobuf
        .write_to_bytes()
        .expect("Failed to serialize protobuf struct")
}

#[test]
fn cbor_sign_and_verify_roundtrip() {
    let private_key = load_private_key();
    let public_key = load_public_key();

    let unsigned_bytes = to_vec(&sample_unsigned_vc()).expect("Failed to encode unsigned VC");
    let signed_bytes = sign_cbor_vc(&unsigned_bytes, &private_key).expect("CBOR signing failed");

    verify_cbor_vc(&signed_bytes, &public_key).expect("CBOR verification failed");
}

#[test]
fn cbor_encode_decode_signed_roundtrip() {
    let private_key = load_private_key();
    let public_key = load_public_key();

    let signed_vc = sample_signed_vc(&private_key);
    let cbor_bytes = encode_signed_vc_to_cbor(&signed_vc).expect("Failed to encode signed VC");
    let decoded_vc = decode_signed_vc_from_cbor(&cbor_bytes).expect("Failed to decode signed VC");

    assert_eq!(signed_vc, decoded_vc);
    verify_cbor_vc(&cbor_bytes, &public_key).expect("CBOR verification failed");
}

#[test]
fn cbor_decode_rejects_invalid_bytes() {
    let invalid = [0xff];

    assert!(decode_unsigned_vc_from_cbor(&invalid).is_err());
    assert!(decode_signed_vc_from_cbor(&invalid).is_err());
}

#[test]
fn cbor_verify_rejects_tampered_payload() {
    let private_key = load_private_key();
    let public_key = load_public_key();

    let unsigned_bytes = to_vec(&sample_unsigned_vc()).expect("Failed to encode unsigned VC");
    let mut signed_bytes =
        sign_cbor_vc(&unsigned_bytes, &private_key).expect("CBOR signing failed");

    assert!(!signed_bytes.is_empty());
    let idx = signed_bytes.len() / 2;
    signed_bytes[idx] ^= 0x01;

    assert!(verify_cbor_vc(&signed_bytes, &public_key).is_err());
}

#[test]
fn protobuf_sign_and_verify_roundtrip() {
    let private_key = load_private_key();
    let public_key = load_public_key();

    let unsigned_bytes = unsigned_vc_to_protobuf_bytes(&sample_unsigned_vc());
    let signed_bytes =
        sign_protobuf_vc(&unsigned_bytes, &private_key).expect("Protobuf signing failed");

    verify_protobuf_vc(&signed_bytes, &public_key).expect("Protobuf verification failed");
}

#[test]
fn protobuf_encode_and_verify_roundtrip() {
    let private_key = load_private_key();
    let public_key = load_public_key();

    let signed_vc = sample_signed_vc(&private_key);
    let protobuf_bytes =
        encode_signed_vc_to_protobuf(&signed_vc).expect("Failed to encode signed VC");

    assert!(decode_signed_vc_from_protobuf(&protobuf_bytes).is_ok());
    verify_protobuf_vc(&protobuf_bytes, &public_key).expect("Protobuf verification failed");
}

#[test]
fn protobuf_decode_rejects_invalid_bytes() {
    // Malformed length-delimited field (truncated payload)
    let invalid = [0x0A];

    assert!(decode_unsigned_vc_from_protobuf(&invalid).is_err());
    assert!(decode_signed_vc_from_protobuf(&invalid).is_err());
}

#[test]
fn protobuf_verify_rejects_tampered_payload() {
    let private_key = load_private_key();
    let public_key = load_public_key();

    let unsigned_bytes = unsigned_vc_to_protobuf_bytes(&sample_unsigned_vc());
    let mut signed_bytes =
        sign_protobuf_vc(&unsigned_bytes, &private_key).expect("Protobuf signing failed");

    assert!(!signed_bytes.is_empty());
    let idx = signed_bytes.len() / 2;
    signed_bytes[idx] ^= 0x01;

    assert!(verify_protobuf_vc(&signed_bytes, &public_key).is_err());
}
