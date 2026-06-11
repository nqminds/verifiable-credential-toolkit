#![cfg(not(target_arch = "wasm32"))]

use c2pa_cbor::to_vec;
use verifiable_credential_toolkit::{
    bindings::{
        cbor::{
            decode_signed_vc_from_cbor, decode_unsigned_vc_from_cbor, encode_signed_vc_to_cbor,
            sign_cbor_vc, verify_cbor_vc,
        },
        protobuf::{
            decode_signed_vc_from_protobuf, decode_unsigned_vc_from_protobuf,
            encode_signed_vc_to_protobuf, encode_unsigned_vc_to_protobuf, sign_protobuf_vc,
            verify_protobuf_vc, Protobuf,
        },
        CredentialCodec,
    },
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
    encode_unsigned_vc_to_protobuf(vc).expect("Failed to encode unsigned VC to protobuf")
}

/// Build an unsigned VC whose `credentialSubject` carries `value`, the arbitrary-JSON
/// `Value` field where number fidelity actually matters.
fn vc_with_subject_value(value: serde_json::Value) -> UnsignedVerifiableCredential {
    serde_json::from_value(serde_json::json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": "https://www.example.com/",
        "credentialSubject": { "id": "subject-id", "value": value }
    }))
    .expect("sample unsigned VC should deserialize")
}

/// Round-trip a `credentialSubject.value` through Protobuf and return what comes back.
fn protobuf_roundtrip_subject_value(value: serde_json::Value) -> serde_json::Value {
    let vc = vc_with_subject_value(value);
    let bytes = encode_unsigned_vc_to_protobuf(&vc).expect("protobuf encode failed");
    let decoded = Protobuf::decode_unsigned(&bytes).expect("protobuf decode failed");
    serde_json::to_value(&decoded).expect("re-serialize decoded VC")["credentialSubject"]["value"]
        .clone()
}

/// Round-trip a `credentialSubject.value` through CBOR and return what comes back.
fn cbor_roundtrip_subject_value(value: serde_json::Value) -> serde_json::Value {
    let vc = vc_with_subject_value(value);
    let bytes = to_vec(&vc).expect("CBOR encode failed");
    let decoded = decode_unsigned_vc_from_cbor(&bytes).expect("CBOR decode failed");
    serde_json::to_value(&decoded).expect("re-serialize decoded VC")["credentialSubject"]["value"]
        .clone()
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

    // The typed schema must round-trip the credential without loss: decoding the
    // protobuf bytes back into the domain type reproduces the original exactly.
    let decoded: VerifiableCredential = Protobuf::decode_signed(&protobuf_bytes)
        .expect("Failed to decode signed VC into domain type");
    assert_eq!(signed_vc, decoded);

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

// --- Number fidelity through each codec ---------------------------------------
//
// Numbers live inside `credentialSubject`, which is arbitrary JSON (`serde_json::Value`).
// Both codecs must round-trip every number type exactly — the decoded JSON must equal
// the original, with integers staying integers, floats staying floats, and full
// precision preserved even beyond 2^53 (where an IEEE-754 double could not represent the
// value). Protobuf achieves this by carrying the dynamic fields as their exact JSON text
// rather than as `google.protobuf.Value`; CBOR has native integer and float types.

/// Every number type round-trips through a codec exactly, at the top level and nested.
fn assert_number_fidelity(roundtrip: fn(serde_json::Value) -> serde_json::Value, codec: &str) {
    for value in [
        serde_json::json!(42),
        serde_json::json!(0),
        serde_json::json!(-100),
        serde_json::json!(9007199254740992i64), // 2^53
        serde_json::json!(9007199254740993i64), // 2^53 + 1, not f64-representable
        serde_json::json!(18446744073709551615u64), // u64::MAX
        serde_json::json!(-9223372036854775808i64), // i64::MIN
        serde_json::json!(1.23456),
        serde_json::json!(0.1),
        serde_json::json!(-2.5),
        serde_json::json!(0.0),
        serde_json::json!(1e10),
        serde_json::json!({"a": [1, 2, {"b": 255}], "c": -7, "f": 1.5}),
    ] {
        assert_eq!(
            roundtrip(value.clone()),
            value,
            "{codec} should preserve {value} exactly"
        );
    }
}

/// Protobuf round-trips every number type in `credentialSubject` exactly: the decoded
/// JSON equals the original, integers stay integers, and precision is never lost.
#[test]
fn protobuf_preserves_all_numbers_exactly() {
    assert_number_fidelity(protobuf_roundtrip_subject_value, "Protobuf");
}

/// CBOR round-trips every number type exactly, same as Protobuf.
#[test]
fn cbor_preserves_all_numbers_exactly() {
    assert_number_fidelity(cbor_roundtrip_subject_value, "CBOR");
}

/// Integers keep their JSON number *type* (not just their value) after a Protobuf
/// round-trip — `42` comes back as the integer `42`, not the float `42.0`.
#[test]
fn protobuf_keeps_integers_as_integers() {
    let after = protobuf_roundtrip_subject_value(serde_json::json!(42));
    assert_eq!(after, serde_json::json!(42));
    assert!(after.is_i64(), "integer must round-trip as an integer, got {after}");
    assert!(!after.is_f64());
}

/// A fully-mixed subject (small int, >2^53 int, float) is byte-identical after Protobuf
/// and CBOR alike.
#[test]
fn protobuf_and_cbor_agree_on_mixed_numbers() {
    let subject = serde_json::json!({
        "small": 7,
        "big": 9007199254740993i64,
        "float": 0.25
    });
    assert_eq!(protobuf_roundtrip_subject_value(subject.clone()), subject);
    assert_eq!(cbor_roundtrip_subject_value(subject.clone()), subject);
}
