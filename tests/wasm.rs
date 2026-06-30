#[cfg(target_arch = "wasm32")]
mod wasm_tests {
    use chrono::{DateTime, Duration, Utc};
    use url::Url;
    use verifiable_credential_toolkit::{
        Algorithm, SchemaSource, SigningKey, UnsignedVerifiableCredential, VerifiableCredential,
        VerifiablePresentation, VerifyingKey,
    };
    use wasm_bindgen_test::*;

    /// Test that a valid Verifiable Credential can be deserialized
    #[wasm_bindgen_test]
    fn valid_vc_deserializes() {
        let vc: VerifiableCredential =
            serde_json::from_str(include_str!("./test_data/verifiable_credentials/vc.json"))
                .expect("Failed to deserialize JSON");

        assert!(serde_json::to_string(&vc).is_ok());
    }

    /// Test that an invalid Verifiable Credential fails to deserialize
    #[wasm_bindgen_test]
    fn invalid_vc_fails_to_deserialize() {
        let vc: Result<VerifiableCredential, _> = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/invalid_vc.json"
        ));

        assert!(vc.is_err());
    }
    /// Test that the OneOrMany<_, PreferOne> serde_as helper works as expected
    #[wasm_bindgen_test]
    fn one_or_many() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned_one_or_many.json"
        ))
        .expect("Failed to deserialize JSON");

        // Test that the single string is deserialized correctly
        assert!(serde_json::to_string(&vc).is_ok());

        let json_vc = serde_json::to_string(&vc).unwrap();

        // Test that the vec is correctly serialized into a single string
        assert!(json_vc.contains(r#""type":"VerifiableCredential""#));
    }

    /// Test the sign method on UnsignedVerifiableCredential
    #[wasm_bindgen_test]
    fn sign_vc() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key = SigningKey::new(
            Algorithm::Ed25519,
            include_bytes!("test_data/keys/key.priv"),
        )
        .expect("Invalid private key");

        let signed_vc = vc.sign(&private_key).unwrap();

        assert!(serde_json::to_string(&signed_vc).is_ok());
    }

    /// Test that two UnsignedVerifiableCredential of equal values but different ordering produce the same signed VerifiableCredential
    #[wasm_bindgen_test]
    fn canonicalisation_sign() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let vc_2: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/canonicalization.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key = SigningKey::new(
            Algorithm::Ed25519,
            include_bytes!("test_data/keys/key.priv"),
        )
        .expect("Invalid private key");

        let signed_vc = vc.sign(&private_key).expect("Failed to sign VC");

        let signed_vc_2 = vc_2.sign(&private_key).expect("Failed to sign VC");

        assert_eq!(signed_vc, signed_vc_2);
    }

    #[wasm_bindgen_test]
    fn sign_with_schema_check() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key = SigningKey::new(
            Algorithm::Ed25519,
            include_bytes!("test_data/keys/key.priv"),
        )
        .expect("Invalid private key");

        let schema_str = include_str!("test_data/schemas/schema.json");
        let schema: serde_json::Value =
            serde_json::from_str(schema_str).expect("Failed to parse schema JSON");

        let signed_vc = vc
            .validate(&SchemaSource::Inline(&schema))
            .and_then(|()| vc.sign(&private_key))
            .expect("Failed to sign VC");

        assert!(serde_json::to_string(&signed_vc).is_ok());
    }

    #[wasm_bindgen_test]
    fn sign_with_schema_check_fail() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key = SigningKey::new(
            Algorithm::Ed25519,
            include_bytes!("test_data/keys/key.priv"),
        )
        .expect("Invalid private key");

        let schema_str = include_str!("test_data/schemas/schema_fail.json");
        let schema: serde_json::Value =
            serde_json::from_str(schema_str).expect("Failed to parse schema JSON");

        let signed_vc = vc
            .validate(&SchemaSource::Inline(&schema))
            .and_then(|()| vc.sign(&private_key));

        assert!(signed_vc.is_err());
    }

    #[wasm_bindgen_test]
    fn signed_to_unsigned() {
        let private_key = SigningKey::new(
            Algorithm::Ed25519,
            include_bytes!("test_data/keys/key.priv"),
        )
        .expect("Invalid private key");

        let vc: VerifiableCredential = serde_json::from_str::<UnsignedVerifiableCredential>(
            include_str!("test_data/verifiable_credentials/unsigned.json"),
        )
        .expect("Failed to deserialize JSON")
        .sign(&private_key)
        .expect("Failed to sign VC");

        let clone_vc = vc.clone();
        let mut unsigned_vc = clone_vc.to_unsigned();

        // Set id of unsigned_vc
        unsigned_vc.id =
            Some(Url::parse("http://example.com/credentials/3732").expect("Invalid URL"));

        let new_signed_vc = unsigned_vc.sign(&private_key).expect("Failed to sign VC");

        println!("{}", serde_json::to_string_pretty(&vc).unwrap());
        println!("{}", serde_json::to_string_pretty(&new_signed_vc).unwrap());

        assert_ne!(vc, new_signed_vc);
    }

    #[wasm_bindgen_test]
    fn customise_proof_using_builder() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key = SigningKey::new(
            Algorithm::Ed25519,
            include_bytes!("test_data/keys/key.priv"),
        )
        .expect("Invalid private key");

        let mut signed_vc = vc.sign(&private_key).unwrap();

        let expires_time: DateTime<Utc> = Utc::now() + Duration::days(1);

        // Customising proof values using builder pattern
        signed_vc.proof = signed_vc
            .proof
            .set_id(Url::parse("http://example.com/credentials/3732").expect("Invalid URL"))
            .set_proof_type("Ed25519Signature2020".to_string())
            .set_proof_purpose("test".to_string())
            .set_expires(expires_time);

        assert!(serde_json::to_string(&signed_vc).is_ok());

        let json_vc = serde_json::to_string(&signed_vc).unwrap();
        // Assert that id: "http://example.com/credentials/3732" is present in the proof
        assert!(json_vc.contains(r#""id":"http://example.com/credentials/3732""#));
        // Assert that type: "Ed25519Signature2020" is present in the proof
        assert!(json_vc.contains(r#""type":"Ed25519Signature2020""#));
    }

    #[wasm_bindgen_test]
    fn customise_proof_manually() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key = SigningKey::new(
            Algorithm::Ed25519,
            include_bytes!("test_data/keys/key.priv"),
        )
        .expect("Invalid private key");

        let mut signed_vc = vc.sign(&private_key).unwrap();

        let expires_time: DateTime<Utc> = Utc::now() + Duration::days(1);

        // Set proof values manually
        signed_vc.proof.expires = Some(expires_time);
        signed_vc.proof.id =
            Some(Url::parse("http://example.com/credentials/3732").expect("Invalid URL"));
        signed_vc.proof.proof_type = "Ed25519Signature2020".to_string();
        signed_vc.proof.proof_purpose = "test".to_string();

        assert!(serde_json::to_string(&signed_vc).is_ok());

        let json_vc = serde_json::to_string(&signed_vc).unwrap();
        // Assert that id: "http://example.com/credentials/3732" is present in the proof
        assert!(json_vc.contains(r#""id":"http://example.com/credentials/3732""#));
        // Assert that type: "Ed25519Signature2020" is present in the proof
        assert!(json_vc.contains(r#""type":"Ed25519Signature2020""#));
    }

    #[wasm_bindgen_test]
    fn build_verifiable_presentation() {
        let vc: VerifiableCredential =
            serde_json::from_str(include_str!("test_data/verifiable_credentials/vc.json"))
                .expect("Failed to deserialize JSON");

        let vp: VerifiablePresentation = VerifiablePresentation {
            presentation_type: vec!["VerifiablePresentation".to_string()],
            verifiable_credential: Some(vec![vc]),
            id: Some(
                Url::parse("urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5").expect("Invalid URL"),
            ),
            holder: None,
            context: vec![Url::parse("https://www.w3.org/ns/credentials/v2").expect("Invalid URL")],
        };

        assert!(serde_json::to_string(&vp).is_ok());
    }

    #[wasm_bindgen_test]
    fn verify_signed_verifiable_credential() {
        let private_key = SigningKey::new(
            Algorithm::Ed25519,
            include_bytes!("test_data/keys/key.priv"),
        )
        .expect("Invalid private key");

        let vc: VerifiableCredential = serde_json::from_str::<UnsignedVerifiableCredential>(
            include_str!("test_data/verifiable_credentials/unsigned.json"),
        )
        .expect("Failed to deserialize JSON")
        .sign(&private_key)
        .expect("Failed to sign VC");

        let public_key =
            VerifyingKey::new(Algorithm::Ed25519, include_bytes!("test_data/keys/key.pub"))
                .expect("Invalid public key");
        let verify_result = vc.verify(&public_key);

        match &verify_result {
            Ok(_) => println!("Verification successful"),
            Err(e) => println!("Verification failed: {:?}", e),
        }
        assert!(verify_result.is_ok());
    }

    #[wasm_bindgen_test]
    fn verify_denies_modified_verifiable_credential() {
        let private_key = SigningKey::new(
            Algorithm::Ed25519,
            include_bytes!("test_data/keys/key.priv"),
        )
        .expect("Invalid private key");

        let vc: VerifiableCredential = serde_json::from_str::<UnsignedVerifiableCredential>(
            include_str!("test_data/verifiable_credentials/unsigned.json"),
        )
        .expect("Failed to deserialize JSON")
        .sign(&private_key)
        .expect("Failed to sign VC");

        let mut vc_serialized = serde_json::to_string(&vc).expect("Failed to serialize VC");

        vc_serialized = vc_serialized.replace("HenryTrustPhone", "AshEvilPhone");

        let edited_vc: VerifiableCredential =
            serde_json::from_str(&vc_serialized).expect("Failed to deserialize JSON");

        let public_key =
            VerifyingKey::new(Algorithm::Ed25519, include_bytes!("test_data/keys/key.pub"))
                .expect("Invalid public key");

        let verify_result = edited_vc.verify(&public_key);

        assert!(verify_result.is_err());
    }

    /// ML-DSA must work at *runtime* on wasm, not just compile: generate a key pair,
    /// sign, and verify for every parameter set, executed in the wasm test runner.
    #[wasm_bindgen_test]
    fn mldsa_sign_verify_on_wasm() {
        use verifiable_credential_toolkit::generate_keypair_bytes;

        let unsigned: UnsignedVerifiableCredential = serde_json::from_value(serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "https://example.com/issuer",
            "credentialSubject": { "id": "did:example:subject", "n": 42 }
        }))
        .expect("Failed to deserialize JSON");

        for algorithm in [Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::MlDsa87] {
            let (private_key, public_key) = generate_keypair_bytes(algorithm);
            let signed = unsigned
                .clone()
                .sign_with_algorithm(algorithm, &private_key)
                .expect("ML-DSA signing should work on wasm");
            signed
                .verify_auto(&public_key)
                .expect("ML-DSA verification should work on wasm");
        }
    }

    // --- JavaScript / wasm-bindgen ABI ----------------------------------------
    // Exercise the #[wasm_bindgen] entry points in src/wasm.rs — the functions JS
    // actually calls — which the Rust-API tests above don't reach.
    use verifiable_credential_toolkit::wasm;

    /// A sample credential as a JsValue, the way JS would pass one in.
    fn sample_credential_js() -> wasm_bindgen::JsValue {
        serde_wasm_bindgen::to_value(&serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "https://example.com/issuer",
            "credentialSubject": { "id": "urn:uuid:device-1", "name": "Sensor A", "count": 42 }
        }))
        .unwrap_or_else(|_| panic!("credential to JsValue"))
    }

    /// generate_keypair → sign → verify over the JS ABI (Ed25519).
    #[wasm_bindgen_test]
    fn js_sign_and_verify_roundtrip() {
        let kp = wasm::generate_keypair();
        let signed = wasm::sign(sample_credential_js(), &kp.signing_key())
            .unwrap_or_else(|_| panic!("js sign failed"));
        let ok = wasm::verify(signed, &kp.verifying_key())
            .unwrap_or_else(|_| panic!("js verify errored"));
        assert!(ok, "freshly signed credential should verify");
    }

    /// The JS `verify` returns `false` (not an error) for a valid-but-wrong key.
    #[wasm_bindgen_test]
    fn js_verify_returns_false_on_wrong_key() {
        let kp = wasm::generate_keypair();
        let other = wasm::generate_keypair();
        let signed = wasm::sign(sample_credential_js(), &kp.signing_key())
            .unwrap_or_else(|_| panic!("js sign failed"));
        let ok = wasm::verify(signed, &other.verifying_key())
            .unwrap_or_else(|_| panic!("js verify errored"));
        assert!(!ok, "wrong key must not verify");
    }

    /// Multi-algorithm JS path: generate_keypair_for → sign_with_algorithm →
    /// verify_auto / verify_with_algorithm (ML-DSA-65).
    #[wasm_bindgen_test]
    fn js_multi_algorithm_sign_verify() {
        let kp = wasm::generate_keypair_for("ML-DSA-65")
            .unwrap_or_else(|_| panic!("generate ML-DSA-65 keypair"));
        let signed =
            wasm::sign_with_algorithm(sample_credential_js(), "ML-DSA-65", &kp.signing_key())
                .unwrap_or_else(|_| panic!("js sign_with_algorithm failed"));
        assert!(wasm::verify_auto(signed.clone(), &kp.verifying_key())
            .unwrap_or_else(|_| panic!("verify_auto errored")));
        assert!(
            wasm::verify_with_algorithm(signed, "ML-DSA-65", &kp.verifying_key())
                .unwrap_or_else(|_| panic!("verify_with_algorithm errored"))
        );
    }

    /// JS verify_with_schema_check passes a matching schema and rejects a non-matching one
    /// (returning false rather than erroring).
    #[wasm_bindgen_test]
    fn js_verify_with_schema_check() {
        let kp = wasm::generate_keypair();
        let signed = wasm::sign(sample_credential_js(), &kp.signing_key())
            .unwrap_or_else(|_| panic!("js sign failed"));

        let good = serde_wasm_bindgen::to_value(
            &serde_json::json!({ "type": "object", "required": ["id", "name"] }),
        )
        .unwrap_or_else(|_| panic!("schema to JsValue"));
        assert!(
            wasm::verify_with_schema_check(signed.clone(), &kp.verifying_key(), good)
                .unwrap_or_else(|_| panic!("verify_with_schema_check errored"))
        );

        let bad = serde_wasm_bindgen::to_value(
            &serde_json::json!({ "type": "object", "required": ["missing_field"] }),
        )
        .unwrap_or_else(|_| panic!("schema to JsValue"));
        assert!(
            !wasm::verify_with_schema_check(signed, &kp.verifying_key(), bad)
                .unwrap_or_else(|_| panic!("verify_with_schema_check errored")),
            "a credential that fails the schema must not verify"
        );
    }

    /// JS CBOR path: encode → sign → verify, plus decode back to a JS object.
    #[wasm_bindgen_test]
    fn js_cbor_sign_verify_and_decode() {
        let kp = wasm::generate_keypair();
        let unsigned = wasm::encode_unsigned_vc_to_cbor(sample_credential_js())
            .unwrap_or_else(|_| panic!("encode cbor"));
        let signed = wasm::sign_cbor_vc(&unsigned, &kp.signing_key())
            .unwrap_or_else(|_| panic!("sign cbor"));
        assert!(wasm::verify_cbor_vc(&signed, &kp.verifying_key())
            .unwrap_or_else(|_| panic!("verify cbor errored")));
        let _decoded =
            wasm::decode_signed_vc_from_cbor(&signed).unwrap_or_else(|_| panic!("decode cbor"));
    }

    /// JS Protobuf path: encode → sign → verify.
    #[wasm_bindgen_test]
    fn js_protobuf_sign_verify() {
        let kp = wasm::generate_keypair();
        let unsigned = wasm::encode_unsigned_vc_to_protobuf(sample_credential_js())
            .unwrap_or_else(|_| panic!("encode protobuf"));
        let signed = wasm::sign_protobuf_vc(&unsigned, &kp.signing_key())
            .unwrap_or_else(|_| panic!("sign protobuf"));
        assert!(wasm::verify_protobuf_vc(&signed, &kp.verifying_key())
            .unwrap_or_else(|_| panic!("verify protobuf errored")));
    }

    /// The multi-algorithm codec JS functions: sign_*_with_algorithm + verify_*_auto over
    /// both CBOR and Protobuf, with ML-DSA.
    #[wasm_bindgen_test]
    fn js_codec_multi_algorithm() {
        let kp = wasm::generate_keypair_for("ML-DSA-44")
            .unwrap_or_else(|_| panic!("generate ML-DSA-44 keypair"));

        let unsigned_cbor = wasm::encode_unsigned_vc_to_cbor(sample_credential_js())
            .unwrap_or_else(|_| panic!("encode cbor"));
        let signed_cbor =
            wasm::sign_cbor_vc_with_algorithm(&unsigned_cbor, "ML-DSA-44", &kp.signing_key())
                .unwrap_or_else(|_| panic!("sign cbor w/ algorithm"));
        assert!(wasm::verify_cbor_vc_auto(&signed_cbor, &kp.verifying_key())
            .unwrap_or_else(|_| panic!("verify_cbor_vc_auto errored")));

        let unsigned_pb = wasm::encode_unsigned_vc_to_protobuf(sample_credential_js())
            .unwrap_or_else(|_| panic!("encode protobuf"));
        let signed_pb =
            wasm::sign_protobuf_vc_with_algorithm(&unsigned_pb, "ML-DSA-44", &kp.signing_key())
                .unwrap_or_else(|_| panic!("sign protobuf w/ algorithm"));
        assert!(
            wasm::verify_protobuf_vc_auto(&signed_pb, &kp.verifying_key())
                .unwrap_or_else(|_| panic!("verify_protobuf_vc_auto errored"))
        );
    }
}
