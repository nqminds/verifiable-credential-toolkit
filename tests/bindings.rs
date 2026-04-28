#![cfg(not(target_arch = "wasm32"))]

use c2pa_cbor::to_vec;
use protobuf::Message;
use serde_json::json;
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
    generate_keypair,
    proto_schemas::vc::UnsignedVerifiableCredential as ProtobufUnsignedVerifiableCredential,
    UnsignedVerifiableCredential, VerifiableCredential,
};

fn load_private_key() -> Vec<u8> {
    std::fs::read("tests/test_data/keys/key.priv").expect("Error reading private key from file")
}

fn load_public_key() -> Vec<u8> {
    std::fs::read("tests/test_data/keys/key.pub").expect("Error reading public key from file")
}

fn sample_unsigned_vc() -> UnsignedVerifiableCredential {
    serde_json::from_str(include_str!(
        "test_data/verifiable_credentials/unsigned.json"
    ))
    .expect("Failed to deserialize JSON")
}

fn sample_signed_vc(private_key: &[u8]) -> VerifiableCredential {
    sample_unsigned_vc()
        .sign(private_key)
        .expect("Failed to sign VC")
}

fn unsigned_vc_to_protobuf_bytes(vc: &UnsignedVerifiableCredential) -> Vec<u8> {
    let mut json_value = serde_json::to_value(vc).expect("Failed to serialize VC to JSON value");
    // Apply the same normalization as encode_signed_vc_to_protobuf:
    // - strip null-valued keys (Option::None fields serialized without skip_serializing_if)
    // - wrap single-string OneOrMany fields back to arrays
    normalize_value_for_protobuf(&mut json_value);
    let json = serde_json::to_string(&json_value).expect("Failed to serialize to JSON string");
    let protobuf: ProtobufUnsignedVerifiableCredential =
        protobuf_json_mapping::parse_from_str(&json)
            .expect("Failed to convert JSON to protobuf struct");

    protobuf
        .write_to_bytes()
        .expect("Failed to serialize protobuf struct")
}

/// Mirror of `normalize_for_protobuf` from src/bindings/protobuf.rs.
/// Applied only to the unsigned VC level (no `proof` key present).
fn normalize_value_for_protobuf(vc_json: &mut serde_json::Value) {
    let Some(obj) = vc_json.as_object_mut() else {
        return;
    };
    obj.retain(|_, v| !v.is_null());
    for key in ["type"] {
        if let Some(field) = obj.get_mut(key) {
            if field.is_string() {
                let s = field.as_str().unwrap().to_string();
                *field = serde_json::Value::Array(vec![serde_json::Value::String(s)]);
            }
        }
    }
}

fn minimal_unsigned_vc() -> UnsignedVerifiableCredential {
    serde_json::from_value(json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": "https://issuer.example.com/",
        "credentialSubject": { "id": "did:example:subject" }
    }))
    .expect("Failed to deserialize minimal unsigned VC")
}

fn rich_unsigned_vc() -> UnsignedVerifiableCredential {
    serde_json::from_value(json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "urn:uuid:aaaabbbb-0000-1111-2222-ccccddddeeee",
        "type": ["VerifiableCredential", "RichCredential"],
        "name": "My Rich Credential",
        "description": "A credential with many optional fields set",
        "issuer": "https://rich.example.com/",
        "validFrom": "2025-01-01T00:00:00Z",
        "validUntil": "2099-12-31T23:59:59Z",
        "credentialSchema": [
            { "id": "https://schema.example.com/first.json", "type": "JsonSchema" },
            { "id": "https://schema.example.com/second.json", "type": "JsonSchema" }
        ],
        "credentialSubject": {
            "id": "did:example:rich-subject",
            "role": "admin",
            "level": 5
        }
    }))
    .expect("Failed to deserialize rich unsigned VC")
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

// ── CBOR field-value tests ───────────────────────────────────────────────────

#[test]
fn cbor_decode_unsigned_preserves_fields() {
    let vc = sample_unsigned_vc();
    let cbor_bytes = to_vec(&vc).expect("Failed to encode unsigned VC to CBOR");
    let decoded = decode_unsigned_vc_from_cbor(&cbor_bytes).expect("Failed to decode CBOR");

    assert_eq!(decoded, vc);
    assert_eq!(
        decoded.issuer,
        serde_json::from_value(json!("https://www.example.com/")).unwrap()
    );
    assert_eq!(
        decoded.credential_subject,
        json!({ "name": "HenryTrustPhone", "id": "HenryTrustPhone-id" })
    );
}

#[test]
fn cbor_signed_decode_preserves_fields() {
    let private_key = load_private_key();

    let unsigned_bytes = to_vec(&sample_unsigned_vc()).expect("Failed to encode unsigned VC");
    let signed_bytes = sign_cbor_vc(&unsigned_bytes, &private_key).expect("CBOR signing failed");
    let decoded = decode_signed_vc_from_cbor(&signed_bytes).expect("Failed to decode signed CBOR");

    assert_eq!(
        decoded.unsigned.issuer,
        serde_json::from_value(json!("https://www.example.com/")).unwrap()
    );
    assert_eq!(decoded.proof.proof_type, "Ed25519Signature2018");
    assert_eq!(decoded.proof.proof_purpose, "assertionMethod");
}

#[test]
fn cbor_empty_bytes_rejected() {
    assert!(decode_unsigned_vc_from_cbor(&[]).is_err());
    assert!(decode_signed_vc_from_cbor(&[]).is_err());
}

#[test]
fn cbor_wrong_public_key_rejected() {
    let private_key = load_private_key();
    let (_, different_public_key) = generate_keypair();

    let unsigned_bytes = to_vec(&sample_unsigned_vc()).expect("Failed to encode unsigned VC");
    let signed_bytes = sign_cbor_vc(&unsigned_bytes, &private_key).expect("CBOR signing failed");

    assert!(verify_cbor_vc(&signed_bytes, &different_public_key).is_err());
}

#[test]
fn cbor_sign_rejects_wrong_key_length() {
    let unsigned_bytes =
        to_vec(&sample_unsigned_vc()).expect("Failed to encode unsigned VC to CBOR");
    let bad_key = vec![0u8; 16]; // 16 bytes instead of 32

    assert!(sign_cbor_vc(&unsigned_bytes, &bad_key).is_err());
}

#[test]
fn cbor_minimal_vc_roundtrip() {
    let (private_key, public_key) = generate_keypair();
    let vc = minimal_unsigned_vc();

    let unsigned_bytes = to_vec(&vc).expect("Failed to encode minimal unsigned VC");
    let signed_bytes = sign_cbor_vc(&unsigned_bytes, &private_key).expect("CBOR signing failed");
    verify_cbor_vc(&signed_bytes, &public_key).expect("CBOR verification of minimal VC failed");
}

#[test]
fn cbor_rich_vc_roundtrip() {
    let (private_key, public_key) = generate_keypair();
    let vc = rich_unsigned_vc();

    let unsigned_bytes = to_vec(&vc).expect("Failed to encode rich unsigned VC");
    let signed_bytes = sign_cbor_vc(&unsigned_bytes, &private_key).expect("CBOR signing failed");
    verify_cbor_vc(&signed_bytes, &public_key).expect("CBOR verification of rich VC failed");
}

#[test]
fn cbor_rich_vc_decode_preserves_optional_fields() {
    let (private_key, _) = generate_keypair();
    let vc = rich_unsigned_vc();

    let unsigned_bytes = to_vec(&vc).expect("Failed to encode rich unsigned VC");
    let signed_bytes = sign_cbor_vc(&unsigned_bytes, &private_key).expect("CBOR signing failed");
    let decoded = decode_signed_vc_from_cbor(&signed_bytes).expect("Failed to decode signed CBOR");

    assert!(decoded.unsigned.valid_until.is_some());
    assert!(decoded.unsigned.name.is_some());
    assert!(decoded.unsigned.description.is_some());
    // Two schemas should be preserved
    let schemas = decoded
        .unsigned
        .credential_schema
        .expect("expected schemas");
    assert_eq!(schemas.len(), 2);
}

#[test]
fn cbor_is_smaller_than_json() {
    let vc = sample_unsigned_vc();
    let cbor_bytes = to_vec(&vc).expect("Failed to encode to CBOR");
    let json_bytes = serde_json::to_vec(&vc).expect("Failed to encode to JSON");
    assert!(
        cbor_bytes.len() < json_bytes.len(),
        "Expected CBOR ({} bytes) to be smaller than JSON ({} bytes)",
        cbor_bytes.len(),
        json_bytes.len()
    );
}

#[test]
fn cbor_two_different_keys_produce_different_signatures() {
    let (private_key_a, _) = generate_keypair();
    let (private_key_b, _) = generate_keypair();

    let unsigned_bytes =
        to_vec(&sample_unsigned_vc()).expect("Failed to encode unsigned VC to CBOR");
    let signed_a = sign_cbor_vc(&unsigned_bytes, &private_key_a).expect("signing failed");
    let signed_b = sign_cbor_vc(&unsigned_bytes, &private_key_b).expect("signing failed");

    assert_ne!(signed_a, signed_b);
}

#[test]
fn cbor_encode_decode_is_identity() {
    let private_key = load_private_key();
    let signed_vc = sample_signed_vc(&private_key);

    let cbor_bytes = encode_signed_vc_to_cbor(&signed_vc).expect("Failed to encode signed VC");
    let decoded = decode_signed_vc_from_cbor(&cbor_bytes).expect("Failed to decode signed CBOR");

    // Full equality: unsigned data + proof must survive the round-trip unchanged.
    assert_eq!(signed_vc, decoded);
}

// ── Protobuf field-value tests ───────────────────────────────────────────────

#[test]
fn protobuf_decode_unsigned_preserves_context() {
    let vc = sample_unsigned_vc();
    let proto_bytes = unsigned_vc_to_protobuf_bytes(&vc);
    let decoded =
        decode_unsigned_vc_from_protobuf(&proto_bytes).expect("Failed to decode unsigned protobuf");

    assert_eq!(
        decoded.context,
        vec!["https://www.w3.org/ns/credentials/v2".to_string()]
    );
    assert_eq!(
        decoded.id.as_ref().map(|s| s.value.as_str()),
        Some("urn:uuid:9a3e3c0e-2db0-412a-95c7-cf5520ba78df")
    );
}

#[test]
fn protobuf_decode_signed_preserves_proof_fields() {
    let private_key = load_private_key();

    let unsigned_bytes = unsigned_vc_to_protobuf_bytes(&sample_unsigned_vc());
    let signed_bytes =
        sign_protobuf_vc(&unsigned_bytes, &private_key).expect("Protobuf signing failed");
    let decoded =
        decode_signed_vc_from_protobuf(&signed_bytes).expect("Failed to decode signed protobuf");

    let proof = decoded.proof.as_ref().expect("expected proof");
    assert_eq!(proof.proof_type, "Ed25519Signature2018");
    assert_eq!(proof.proof_purpose, "assertionMethod");
    assert!(!proof.proof_value.is_empty());
}

#[test]
fn protobuf_empty_bytes_rejected_for_unsigned() {
    // An empty protobuf payload is valid structurally but all fields are at
    // default/empty values. The id field and context will be empty, but
    // parse_from_bytes itself should succeed (protobuf allows empty messages).
    // The subsequent domain-model conversion (protobuf_unsigned_to_domain) is
    // what validates required fields. Here we test that signing empty protobuf
    // bytes fails because the domain conversion will reject the empty VC.
    let empty_bytes: &[u8] = &[];
    let (private_key, _) = generate_keypair();
    assert!(sign_protobuf_vc(empty_bytes, &private_key).is_err());
}

#[test]
fn protobuf_wrong_public_key_rejected() {
    let private_key = load_private_key();
    let (_, different_public_key) = generate_keypair();

    let unsigned_bytes = unsigned_vc_to_protobuf_bytes(&sample_unsigned_vc());
    let signed_bytes =
        sign_protobuf_vc(&unsigned_bytes, &private_key).expect("Protobuf signing failed");

    assert!(verify_protobuf_vc(&signed_bytes, &different_public_key).is_err());
}

#[test]
fn protobuf_sign_rejects_wrong_key_length() {
    let unsigned_bytes = unsigned_vc_to_protobuf_bytes(&sample_unsigned_vc());
    let bad_key = vec![0u8; 16]; // 16 bytes instead of 32

    assert!(sign_protobuf_vc(&unsigned_bytes, &bad_key).is_err());
}

#[test]
fn protobuf_minimal_vc_roundtrip() {
    let (private_key, public_key) = generate_keypair();
    let vc = minimal_unsigned_vc();

    let proto_bytes = unsigned_vc_to_protobuf_bytes(&vc);
    let signed_bytes =
        sign_protobuf_vc(&proto_bytes, &private_key).expect("Protobuf signing failed");
    verify_protobuf_vc(&signed_bytes, &public_key)
        .expect("Protobuf verification of minimal VC failed");
}

#[test]
fn protobuf_rich_vc_roundtrip() {
    let (private_key, public_key) = generate_keypair();
    let vc = rich_unsigned_vc();

    let proto_bytes = unsigned_vc_to_protobuf_bytes(&vc);
    let signed_bytes =
        sign_protobuf_vc(&proto_bytes, &private_key).expect("Protobuf signing failed");
    verify_protobuf_vc(&signed_bytes, &public_key)
        .expect("Protobuf verification of rich VC failed");
}

#[test]
fn protobuf_encode_decode_signed_roundtrip() {
    let private_key = load_private_key();
    let public_key = load_public_key();

    let signed_vc = sample_signed_vc(&private_key);
    let proto_bytes = encode_signed_vc_to_protobuf(&signed_vc).expect("Failed to encode signed VC");
    let decoded_proto =
        decode_signed_vc_from_protobuf(&proto_bytes).expect("Failed to decode signed protobuf");

    // Context survives the round-trip
    assert_eq!(
        decoded_proto.context,
        vec!["https://www.w3.org/ns/credentials/v2".to_string()]
    );
    // Proof is present
    assert!(decoded_proto.proof.is_some());

    // And the bytes are still verifiable
    verify_protobuf_vc(&proto_bytes, &public_key).expect("Protobuf verification failed");
}

#[test]
fn protobuf_two_different_keys_produce_different_signatures() {
    let (private_key_a, _) = generate_keypair();
    let (private_key_b, _) = generate_keypair();

    let unsigned_bytes = unsigned_vc_to_protobuf_bytes(&sample_unsigned_vc());
    let signed_a = sign_protobuf_vc(&unsigned_bytes, &private_key_a).expect("signing failed");
    let signed_b = sign_protobuf_vc(&unsigned_bytes, &private_key_b).expect("signing failed");

    assert_ne!(signed_a, signed_b);
}

// ── Cross-format consistency tests ──────────────────────────────────────────

/// Sign the same unsigned VC via both formats and confirm that each signed form
/// verifies only with the matching public key and fails with a different one.
#[test]
fn cbor_and_protobuf_verify_independently() {
    let (private_key, public_key) = generate_keypair();
    let (_, other_public_key) = generate_keypair();

    let vc = sample_unsigned_vc();

    let cbor_signed =
        sign_cbor_vc(&to_vec(&vc).expect("encode"), &private_key).expect("CBOR signing failed");

    let proto_signed = sign_protobuf_vc(&unsigned_vc_to_protobuf_bytes(&vc), &private_key)
        .expect("Protobuf signing failed");

    // Both verify with correct key
    verify_cbor_vc(&cbor_signed, &public_key).expect("CBOR verification failed");
    verify_protobuf_vc(&proto_signed, &public_key).expect("Protobuf verification failed");

    // Neither verifies with wrong key
    assert!(verify_cbor_vc(&cbor_signed, &other_public_key).is_err());
    assert!(verify_protobuf_vc(&proto_signed, &other_public_key).is_err());
}

/// The unsigned VC recovered from the CBOR signed form equals the one recovered
/// from the Protobuf signed form (same credential data, different encoding).
#[test]
fn cbor_and_protobuf_preserve_same_credential_data() {
    let (private_key, _) = generate_keypair();
    let vc = sample_unsigned_vc();

    let cbor_signed =
        sign_cbor_vc(&to_vec(&vc).expect("encode"), &private_key).expect("CBOR signing failed");

    let proto_signed = sign_protobuf_vc(&unsigned_vc_to_protobuf_bytes(&vc), &private_key)
        .expect("Protobuf signing failed");

    let cbor_decoded =
        decode_signed_vc_from_cbor(&cbor_signed).expect("Failed to decode CBOR signed VC");
    let proto_decoded_raw =
        decode_signed_vc_from_protobuf(&proto_signed).expect("Failed to decode Protobuf signed VC");
    let proto_decoded_json = protobuf_json_mapping::print_to_string(&proto_decoded_raw)
        .expect("protobuf->json conversion failed");
    let proto_decoded: VerifiableCredential = serde_json::from_str(&proto_decoded_json)
        .expect("json->VerifiableCredential conversion failed");

    // The unsigned portion should be identical across formats
    assert_eq!(cbor_decoded.unsigned, proto_decoded.unsigned);
}

/// Signing with one format and verifying with the other should fail because
/// the encoded bytes are format-specific.
#[test]
fn cbor_bytes_are_not_valid_protobuf() {
    let (private_key, public_key) = generate_keypair();

    let cbor_signed = sign_cbor_vc(
        &to_vec(&sample_unsigned_vc()).expect("encode"),
        &private_key,
    )
    .expect("CBOR signing failed");

    // Trying to verify CBOR bytes as Protobuf must fail (wrong format).
    assert!(verify_protobuf_vc(&cbor_signed, &public_key).is_err());
}

/// Regression: a VC whose `type` array has only one element is collapsed to a
/// bare string by `serde_with::OneOrMany<_, PreferOne>`.  The protobuf encode
/// path must re-wrap it so that `protobuf_json_mapping` does not reject it.
#[test]
fn protobuf_single_type_vc_roundtrip() {
    let (private_key, public_key) = generate_keypair();

    // minimal_unsigned_vc has exactly one credential type.
    let vc = minimal_unsigned_vc();
    let proto_bytes = unsigned_vc_to_protobuf_bytes(&vc);
    let signed_bytes =
        sign_protobuf_vc(&proto_bytes, &private_key).expect("Protobuf signing failed");
    verify_protobuf_vc(&signed_bytes, &public_key)
        .expect("Protobuf verification of single-type VC failed");
}
