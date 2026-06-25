#![cfg(not(target_arch = "wasm32"))]

use c2pa_cbor::to_vec;
use verifiable_credential_toolkit::{
    bindings::{
        cbor::{
            decode_signed_vc_from_cbor, decode_unsigned_vc_from_cbor, encode_signed_vc_to_cbor,
            sign_cbor_vc, sign_cbor_vc_with_algorithm, verify_cbor_vc, verify_cbor_vc_auto,
            verify_cbor_vc_with_algorithm, Cbor,
        },
        protobuf::{
            decode_signed_vc_from_protobuf, decode_unsigned_vc_from_protobuf,
            encode_signed_vc_to_protobuf, encode_unsigned_vc_to_protobuf, sign_protobuf_vc,
            sign_protobuf_vc_with_algorithm, verify_protobuf_vc, verify_protobuf_vc_auto,
            verify_protobuf_vc_with_algorithm, Protobuf,
        },
        CredentialCodec,
    },
    generate_keypair_bytes, Algorithm, SigningKey, UnsignedVerifiableCredential, VcError,
    VerifiableCredential, VerifyingKey,
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

/// A codec-level decode failure surfaces through the `CredentialCodec` trait as
/// `VcError::Codec` (the variant that wraps a format-specific error), for both formats.
#[test]
fn codec_decode_failure_maps_to_vcerror_codec() {
    let truncated_protobuf = [0x0A]; // length-delimited field header with no payload
    assert!(matches!(
        Protobuf::decode_unsigned(&truncated_protobuf),
        Err(VcError::Codec(_))
    ));

    let invalid_cbor = [0xff];
    assert!(matches!(
        Cbor::decode_unsigned(&invalid_cbor),
        Err(VcError::Codec(_))
    ));
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
        serde_json::json!(9007199254740992i64),     // 2^53
        serde_json::json!(9007199254740993i64),     // 2^53 + 1, not f64-representable
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
    assert!(
        after.is_i64(),
        "integer must round-trip as an integer, got {after}"
    );
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

// --- Full-credential and codec-branch coverage --------------------------------

/// A maximally-populated unsigned credential: object-form `issuer`/`name`/`description`
/// (with numbers inside them), a big integer and a nested `null` in `credentialSubject`,
/// nanosecond timestamps, a `credentialStatus`, and a multi-element `credentialSchema`.
/// Exercises every dynamic-JSON field and the optional typed fields at once.
fn kitchen_sink_unsigned_json() -> serde_json::Value {
    serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "urn:uuid:9a3e3c0e-2db0-412a-95c7-cf5520ba78df",
        "type": ["VerifiableCredential", "ExampleCredential"],
        "name": { "@value": "Example Credential", "@language": "en" },
        "description": "A plain-string description",
        "issuer": { "id": "https://example.com/issuer", "name": "Example Org", "rank": 7 },
        "credentialSubject": {
            "id": "did:example:subject",
            "count": 42,
            "big": 9007199254740993i64,
            "ratio": 0.25,
            "nested": { "flag": true, "missing": null, "list": [1, "two", 3.5] }
        },
        "validFrom": "2024-08-22T13:53:32.295644150Z",
        "validUntil": "2030-01-01T00:00:00.000000001Z",
        "credentialStatus": { "id": "https://example.com/status/1", "type": "StatusList2021Entry" },
        "credentialSchema": [
            { "id": "https://example.com/schema-a.json", "type": "JsonSchema" },
            { "id": "https://example.com/schema-b.json", "type": "JsonSchema" }
        ]
    })
}

/// The fully-populated unsigned credential round-trips through Protobuf with no loss:
/// object-form polymorphic fields, numbers inside them, nested nulls, nanosecond
/// timestamps, status, and multi-element schema all come back identical.
#[test]
fn protobuf_full_unsigned_credential_roundtrip() {
    let vc: UnsignedVerifiableCredential =
        serde_json::from_value(kitchen_sink_unsigned_json()).expect("kitchen-sink should parse");

    let bytes = encode_unsigned_vc_to_protobuf(&vc).expect("encode failed");
    let decoded = Protobuf::decode_unsigned(&bytes).expect("decode failed");

    assert_eq!(vc, decoded);
}

/// The same rich credential signs and verifies through Protobuf, and the decoded
/// unsigned payload still equals the original — proving the lossless round-trip holds
/// under signature verification (the signature is over the JSON, which must reproduce
/// byte-for-byte).
#[test]
fn protobuf_full_credential_signs_and_verifies() {
    let private_key = load_private_key();
    let public_key = load_public_key();

    let vc: UnsignedVerifiableCredential =
        serde_json::from_value(kitchen_sink_unsigned_json()).expect("kitchen-sink should parse");
    let unsigned_bytes = encode_unsigned_vc_to_protobuf(&vc).expect("encode failed");

    let signed_bytes = sign_protobuf_vc(&unsigned_bytes, &private_key).expect("signing failed");
    verify_protobuf_vc(&signed_bytes, &public_key).expect("verification failed");

    let decoded = Protobuf::decode_signed(&signed_bytes).expect("decode failed");
    assert_eq!(decoded.unsigned, vc);
}

/// Every optional `Proof` field round-trips, including the `domain`/`nonce` `OneOrMany`
/// coercion (single `domain` -> array, multi-element `nonce` left as-is). This is a
/// structural round-trip on a fabricated proof — it asserts encode/decode equality, not
/// signature validity, since those coercion branches are never reached by `sign()`.
#[test]
fn protobuf_full_proof_fields_roundtrip() {
    let signed: VerifiableCredential = serde_json::from_value(serde_json::json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": "https://www.example.com/",
        "credentialSubject": { "id": "subject-id" },
        "proof": {
            "id": "urn:uuid:proof-1",
            "type": "DataIntegrityProof",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:example:issuer#key-1",
            "cryptosuite": "eddsa-2022",
            "created": "2024-08-22T13:53:32.295644150Z",
            "expires": "2030-01-01T00:00:00.000000001Z",
            "domain": "https://example.com",
            "challenge": "abc123",
            "proofValue": "z2DeadBeefSignatureValueForStructuralRoundTripOnly",
            "previousProof": "urn:uuid:prev-proof",
            "nonce": ["nonce-1", "nonce-2"]
        }
    }))
    .expect("fabricated signed VC should parse");

    let bytes = encode_signed_vc_to_protobuf(&signed).expect("encode failed");
    let decoded = Protobuf::decode_signed(&bytes).expect("decode failed");

    assert_eq!(signed, decoded);
}

/// `credentialSubject` may be an array of subjects (spec-valid), not just an object.
/// Both codecs must round-trip that shape losslessly.
#[test]
fn codecs_preserve_array_credential_subject() {
    let vc: UnsignedVerifiableCredential = serde_json::from_value(serde_json::json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": "https://www.example.com/",
        "credentialSubject": [
            { "id": "did:example:1", "n": 1 },
            { "id": "did:example:2", "n": 9007199254740993i64 }
        ]
    }))
    .expect("array-subject VC should parse");

    let pb = encode_unsigned_vc_to_protobuf(&vc).expect("protobuf encode");
    assert_eq!(Protobuf::decode_unsigned(&pb).expect("protobuf decode"), vc);

    let cbor = to_vec(&vc).expect("cbor encode");
    assert_eq!(
        decode_unsigned_vc_from_cbor(&cbor).expect("cbor decode"),
        vc
    );
}

/// A `null` nested inside `credentialSubject` survives the Protobuf round-trip — the
/// dynamic field is stored as exact JSON text, so nested nulls are not stripped (only
/// absent top-level optional fields are).
#[test]
fn protobuf_preserves_nested_null_in_subject() {
    let subject = serde_json::json!({ "id": "x", "maybe": null, "deep": { "also": null } });
    assert_eq!(protobuf_roundtrip_subject_value(subject.clone()), subject);
}

/// A single-element `credentialStatus.type` is coerced to an array for the `repeated`
/// protobuf field and comes back as the original single-element vec.
#[test]
fn protobuf_credential_status_roundtrips() {
    let vc: UnsignedVerifiableCredential = serde_json::from_value(serde_json::json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": "https://www.example.com/",
        "credentialSubject": { "id": "subject-id" },
        "credentialStatus": { "id": "https://example.com/status/1", "type": "StatusList2021Entry" }
    }))
    .expect("VC with status should parse");

    let bytes = encode_unsigned_vc_to_protobuf(&vc).expect("encode failed");
    let decoded = Protobuf::decode_unsigned(&bytes).expect("decode failed");

    assert_eq!(vc, decoded);
}

/// The signature is computed over the credential's JSON, so it is independent of the
/// transport codec: a credential signed once verifies after being re-encoded through
/// either CBOR or Protobuf, and the decoded credential is identical in both.
#[test]
fn signature_is_independent_of_codec() {
    let private_key = load_private_key();
    let public_key = load_public_key();

    let unsigned: UnsignedVerifiableCredential =
        serde_json::from_value(kitchen_sink_unsigned_json()).expect("kitchen-sink should parse");
    let signed = unsigned.sign(&private_key).expect("signing failed");

    // Protobuf transport.
    let pb = encode_signed_vc_to_protobuf(&signed).expect("protobuf encode failed");
    verify_protobuf_vc(&pb, &public_key).expect("protobuf verification failed");
    assert_eq!(
        Protobuf::decode_signed(&pb).expect("protobuf decode"),
        signed
    );

    // CBOR transport.
    let cbor = encode_signed_vc_to_cbor(&signed).expect("cbor encode failed");
    verify_cbor_vc(&cbor, &public_key).expect("cbor verification failed");
    assert_eq!(
        decode_signed_vc_from_cbor(&cbor).expect("cbor decode"),
        signed
    );
}

/// Regression: an object-form `issuer` carrying several extra properties must sign and
/// verify reliably after a round-trip. Those properties live in a `HashMap`, whose
/// iteration order is randomized per instance; before signing was JCS-canonicalized
/// (RFC 8785), the re-serialized credential's bytes differed from what was signed and
/// verification failed non-deterministically (measured 20/20 failures). Canonicalization
/// sorts keys, so the signed bytes are stable. Repeated to defeat the previous ~1-in-n!
/// chance of an accidental order match.
#[test]
fn signing_is_stable_for_object_issuer_with_extra_properties() {
    let private_key = load_private_key();
    let public_key = load_public_key();

    for _ in 0..25 {
        let unsigned: UnsignedVerifiableCredential = serde_json::from_value(serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": {
                "id": "https://example.com/issuer",
                "name": "Example Org",
                "region": "EU",
                "tier": "gold",
                "rank": 7
            },
            "credentialSubject": { "id": "subject-id" }
        }))
        .expect("object-issuer VC should parse");

        let signed = unsigned.sign(&private_key).expect("signing failed");

        let pb = encode_signed_vc_to_protobuf(&signed).expect("protobuf encode failed");
        verify_protobuf_vc(&pb, &public_key).expect("protobuf verification after round-trip");

        let cbor = encode_signed_vc_to_cbor(&signed).expect("cbor encode failed");
        verify_cbor_vc(&cbor, &public_key).expect("cbor verification after round-trip");
    }
}

// --- ML-DSA over CBOR and Protobuf, and cross-format interop ------------------

/// Every supported algorithm signs and verifies through both codecs (verify_auto reads
/// the cryptosuite; verify_with_algorithm is explicit).
#[test]
fn all_algorithms_sign_verify_via_cbor_and_protobuf() {
    for algorithm in [
        Algorithm::Ed25519,
        Algorithm::MlDsa44,
        Algorithm::MlDsa65,
        Algorithm::MlDsa87,
    ] {
        let (private_key, public_key) = generate_keypair_bytes(algorithm);

        // CBOR
        let unsigned_cbor = to_vec(&sample_unsigned_vc()).expect("cbor encode unsigned");
        let signed_cbor = sign_cbor_vc_with_algorithm(&unsigned_cbor, algorithm, &private_key)
            .unwrap_or_else(|e| panic!("cbor sign failed for {algorithm:?}: {e}"));
        verify_cbor_vc_auto(&signed_cbor, &public_key)
            .unwrap_or_else(|e| panic!("cbor verify_auto failed for {algorithm:?}: {e}"));
        verify_cbor_vc_with_algorithm(&signed_cbor, algorithm, &public_key)
            .unwrap_or_else(|e| panic!("cbor verify_with_algorithm failed for {algorithm:?}: {e}"));

        // Protobuf
        let unsigned_pb = encode_unsigned_vc_to_protobuf(&sample_unsigned_vc())
            .expect("protobuf encode unsigned");
        let signed_pb = sign_protobuf_vc_with_algorithm(&unsigned_pb, algorithm, &private_key)
            .unwrap_or_else(|e| panic!("protobuf sign failed for {algorithm:?}: {e}"));
        verify_protobuf_vc_auto(&signed_pb, &public_key)
            .unwrap_or_else(|e| panic!("protobuf verify_auto failed for {algorithm:?}: {e}"));
        verify_protobuf_vc_with_algorithm(&signed_pb, algorithm, &public_key).unwrap_or_else(|e| {
            panic!("protobuf verify_with_algorithm failed for {algorithm:?}: {e}")
        });
    }
}

/// The signature is over the format-independent JCS canonical form, so an ML-DSA
/// credential signed in one representation verifies in every other — the interop
/// guarantee. Sign via the JSON core, then verify the same credential as CBOR and as
/// Protobuf; and sign via CBOR, then verify after transcoding to Protobuf.
#[test]
fn mldsa_signature_is_interoperable_across_formats() {
    let (private_key, public_key) = generate_keypair_bytes(Algorithm::MlDsa65);

    // Signed once via the core JSON path.
    let signed = sample_unsigned_vc()
        .sign_with_algorithm(Algorithm::MlDsa65, &private_key)
        .expect("core sign");

    // Verifies as CBOR and as Protobuf.
    let cbor = encode_signed_vc_to_cbor(&signed).expect("cbor encode");
    verify_cbor_vc_auto(&cbor, &public_key).expect("verify cbor");
    let protobuf = encode_signed_vc_to_protobuf(&signed).expect("protobuf encode");
    verify_protobuf_vc_auto(&protobuf, &public_key).expect("verify protobuf");

    // Signed via the CBOR pipeline, transcoded to Protobuf, still verifies.
    let unsigned_cbor = to_vec(&sample_unsigned_vc()).expect("cbor encode unsigned");
    let signed_cbor = sign_cbor_vc_with_algorithm(&unsigned_cbor, Algorithm::MlDsa65, &private_key)
        .expect("cbor sign");
    let transcoded = encode_signed_vc_to_protobuf(
        &decode_signed_vc_from_cbor(&signed_cbor).expect("decode cbor"),
    )
    .expect("re-encode protobuf");
    verify_protobuf_vc_auto(&transcoded, &public_key).expect("verify transcoded");
}
