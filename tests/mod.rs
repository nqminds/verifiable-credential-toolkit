#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use chrono::{DateTime, Duration, Utc};
    use url::Url;
    use verifiable_credential_toolkit::{
        generate_keypair, generate_keypair_bytes, Algorithm, Holder, HolderObject, Issuer,
        IssuerObject, Proof, SchemaSource, SigningKey, UnsignedVerifiableCredential, VcError,
        VerifiableCredential, VerifiablePresentation, VerifyingKey,
    };

    /// Load the test signing key from disk (raw 32-byte Ed25519 seed).
    fn signing_key() -> SigningKey {
        SigningKey::new(
            Algorithm::Ed25519,
            &std::fs::read("tests/test_data/keys/key.priv").expect("read private key"),
        )
        .expect("valid private key")
    }

    /// Load the test verifying key from disk (raw 32-byte Ed25519 key).
    fn verifying_key() -> VerifyingKey {
        VerifyingKey::new(
            Algorithm::Ed25519,
            &std::fs::read("tests/test_data/keys/key.pub").expect("read public key"),
        )
        .expect("valid public key")
    }

    /// Test that a valid Verifiable Credential can be deserialized
    #[test]
    fn valid_vc_deserializes() {
        let vc: VerifiableCredential =
            serde_json::from_str(include_str!("test_data/verifiable_credentials/vc.json"))
                .expect("Failed to deserialize JSON");

        assert!(serde_json::to_string(&vc).is_ok());
    }

    /// The committed `vc.json` fixture carries a real signature over the test key. Verify
    /// it against the stored `proofValue` (not a freshly-signed one), so that any change
    /// to the canonicalization or proof format that would invalidate existing credentials
    /// is caught here rather than passing silently.
    #[test]
    fn vc_json_fixture_signature_verifies() {
        let vc: VerifiableCredential =
            serde_json::from_str(include_str!("test_data/verifiable_credentials/vc.json"))
                .expect("Failed to deserialize JSON");

        vc.verify(&verifying_key())
            .expect("stored vc.json signature should verify");
    }

    /// Test that an invalid Verifiable Credential fails to deserialize
    #[test]
    fn invalid_vc_fails_to_deserialize() {
        let vc: Result<VerifiableCredential, _> = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/invalid_vc.json"
        ));

        assert!(vc.is_err());
    }

    /// Test that the OneOrMany<_, PreferOne> serde_as helper works as expected
    #[test]
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
    #[test]
    fn sign_vc() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key = signing_key();

        let signed_vc = vc.sign(&private_key).unwrap();

        assert!(serde_json::to_string(&signed_vc).is_ok());
    }

    /// Build a credential via the builder, then sign and verify it round-trip.
    #[test]
    fn build_sign_verify_with_builder() {
        let private_key = signing_key();
        let public_key = verifying_key();

        let vc = UnsignedVerifiableCredential::builder(
            vec![Url::parse("https://www.w3.org/ns/credentials/v2").unwrap()],
            vec!["VerifiableCredential".to_string()],
            Issuer::Url(Url::parse("https://example.com/issuer").unwrap()),
            serde_json::json!({ "id": "urn:uuid:device-1", "name": "Sensor A" }),
        )
        .id(Url::parse("urn:uuid:9a3e3c0e-2db0-412a-95c7-cf5520ba78df").unwrap())
        .valid_from(Utc::now() - Duration::days(1))
        .build();

        let signed_vc = vc.sign(&private_key).expect("Failed to sign builder VC");
        signed_vc
            .verify(&public_key)
            .expect("Failed to verify builder VC");
    }

    /// Test that two UnsignedVerifiableCredential of equal values but different ordering produce the same signed VerifiableCredential
    #[test]
    fn canonicalisation_sign() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let vc_2: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/canonicalization.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key = signing_key();

        let signed_vc = vc.sign(&private_key).expect("Failed to sign VC");

        let signed_vc_2 = vc_2.sign(&private_key).expect("Failed to sign VC");

        assert_eq!(signed_vc, signed_vc_2);
    }

    #[test]
    fn sign_with_schema_check() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key = signing_key();

        let schema_str = include_str!("test_data/schemas/schema.json");
        let schema: serde_json::Value =
            serde_json::from_str(schema_str).expect("Failed to parse schema JSON");

        let signed_vc = vc
            .validate(&SchemaSource::Inline(&schema))
            .and_then(|()| vc.sign(&private_key))
            .expect("Failed to sign VC");

        assert!(serde_json::to_string(&signed_vc).is_ok());
    }

    #[test]
    fn sign_with_schema_check_fail() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key = signing_key();

        let schema_str = include_str!("test_data/schemas/schema_fail.json");
        let schema: serde_json::Value =
            serde_json::from_str(schema_str).expect("Failed to parse schema JSON");

        let signed_vc = vc
            .validate(&SchemaSource::Inline(&schema))
            .and_then(|()| vc.sign(&private_key));

        assert!(matches!(signed_vc, Err(VcError::SchemaMismatch)));
    }

    #[test]
    fn signed_to_unsigned() {
        let private_key = signing_key();

        let original_unsigned: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let vc = original_unsigned
            .clone()
            .sign(&private_key)
            .expect("Failed to sign VC");

        // to_unsigned strips the proof and yields back the original credential
        assert_eq!(vc.clone().to_unsigned(), original_unsigned);

        // Re-signing a modified unsigned VC produces a different signed VC
        let mut unsigned_vc = vc.clone().to_unsigned();
        unsigned_vc.id =
            Some(Url::parse("http://example.com/credentials/3732").expect("Invalid URL"));
        let new_signed_vc = unsigned_vc.sign(&private_key).expect("Failed to sign VC");

        assert_ne!(vc, new_signed_vc);
    }

    #[test]
    #[ignore]
    fn sign_with_schema_check_url() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key = signing_key();

        let signed_vc = vc
            .validate(&SchemaSource::Url("https://json.schemastore.org/any.json"))
            .and_then(|()| vc.sign(&private_key))
            .expect("Failed to sign VC");

        assert!(serde_json::to_string(&signed_vc).is_ok());
    }

    #[test]
    fn sign_with_schema_check_url_fails() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key = signing_key();

        let signed_vc = vc
            .validate(&SchemaSource::Url(
                "http://localhost:8000/DoesNotExist.json",
            ))
            .and_then(|()| vc.sign(&private_key));

        assert!(signed_vc.is_err());
    }

    #[test]
    fn customise_proof_using_builder() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key = signing_key();

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

    #[test]
    fn customise_proof_manually() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key = signing_key();

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

    #[test]
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

    #[test]
    fn verify_signed_verifiable_credential() {
        let private_key = signing_key();

        let vc: VerifiableCredential = serde_json::from_str::<UnsignedVerifiableCredential>(
            include_str!("test_data/verifiable_credentials/unsigned.json"),
        )
        .expect("Failed to deserialize JSON")
        .sign(&private_key)
        .expect("Failed to sign VC");

        let public_key = verifying_key();

        let verify_result = vc.verify(&public_key);

        match &verify_result {
            Ok(_) => println!("Verification successful"),
            Err(e) => println!("Verification failed: {:?}", e),
        }
        assert!(verify_result.is_ok());
    }

    #[test]
    fn verify_denies_modified_verifiable_credential() {
        let private_key = signing_key();

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

        let public_key = verifying_key();

        let verify_result = edited_vc.verify(&public_key);

        assert!(matches!(
            verify_result,
            Err(VcError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn deseralize_invalid_vc() {
        let vc: Result<VerifiableCredential, _> = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/invalid_vc.json"
        ));

        if let Err(ref e) = vc {
            println!("{}", e);
        }

        assert!(vc.is_err());
    }

    #[test]
    fn valid_from_verification_true_negative() {
        let private_key = signing_key();
        let public_key = verifying_key();

        let signed_vc = serde_json::from_str::<UnsignedVerifiableCredential>(include_str!(
            "test_data/verifiable_credentials/unsigned_validFrom_invalid.json"
        ))
        .expect("Failed to deserialize JSON")
        .sign(&private_key)
        .expect("Failed to sign VC");

        let verify_result = signed_vc.verify(&public_key);

        assert!(matches!(verify_result, Err(VcError::NotYetValid)));
    }

    #[test]
    fn valid_until_verification_true_negative() {
        let private_key = signing_key();
        let public_key = verifying_key();

        let signed_vc = serde_json::from_str::<UnsignedVerifiableCredential>(include_str!(
            "test_data/verifiable_credentials/unsigned_validUntil_invalid.json"
        ))
        .expect("Failed to deserialize JSON")
        .sign(&private_key)
        .expect("Failed to sign VC");

        let verify_result = signed_vc.verify(&public_key);

        assert!(matches!(verify_result, Err(VcError::Expired)));
    }

    #[test]
    fn valid_from_verification_true_positive() {
        let private_key = signing_key();
        let public_key = verifying_key();

        let signed_vc = serde_json::from_str::<UnsignedVerifiableCredential>(include_str!(
            "test_data/verifiable_credentials/unsigned_validFrom_valid.json"
        ))
        .expect("Failed to deserialize JSON")
        .sign(&private_key)
        .expect("Failed to sign VC");

        let verify_result = signed_vc.verify(&public_key);

        assert!(verify_result.is_ok());
    }

    #[test]
    fn valid_until_verification_true_positive() {
        let private_key = signing_key();
        let public_key = verifying_key();

        let signed_vc = serde_json::from_str::<UnsignedVerifiableCredential>(include_str!(
            "test_data/verifiable_credentials/unsigned_validUntil_valid.json"
        ))
        .expect("Failed to deserialize JSON")
        .sign(&private_key)
        .expect("Failed to sign VC");

        let verify_result = signed_vc.verify(&public_key);

        assert!(verify_result.is_ok());
    }

    /// Boundary: `validFrom` exactly "now" at construction is valid — verification runs a
    /// moment later, so `now >= validFrom` holds. The lower bound is inclusive, not
    /// strictly-after (guards the `<` vs `<=` choice in verify()).
    #[test]
    fn valid_from_at_now_is_valid() {
        let signed = UnsignedVerifiableCredential::builder(
            vec![Url::parse("https://www.w3.org/ns/credentials/v2").unwrap()],
            vec!["VerifiableCredential".to_string()],
            Issuer::Url(Url::parse("https://example.com/issuer").unwrap()),
            serde_json::json!({ "id": "did:example:subject" }),
        )
        .valid_from(Utc::now())
        .build()
        .sign(&signing_key())
        .expect("Failed to sign VC");

        assert!(signed.verify(&verifying_key()).is_ok());
    }

    /// Boundary: `validUntil` one second in the past is expired.
    #[test]
    fn valid_until_just_past_is_expired() {
        let signed = UnsignedVerifiableCredential::builder(
            vec![Url::parse("https://www.w3.org/ns/credentials/v2").unwrap()],
            vec!["VerifiableCredential".to_string()],
            Issuer::Url(Url::parse("https://example.com/issuer").unwrap()),
            serde_json::json!({ "id": "did:example:subject" }),
        )
        .valid_until(Utc::now() - Duration::seconds(1))
        .build()
        .sign(&signing_key())
        .expect("Failed to sign VC");

        assert!(matches!(
            signed.verify(&verifying_key()),
            Err(VcError::Expired)
        ));
    }

    /// Boundary: with both bounds set and "now" strictly inside the window, the
    /// credential verifies (neither NotYetValid nor Expired triggers).
    #[test]
    fn valid_window_currently_inside_is_valid() {
        let signed = UnsignedVerifiableCredential::builder(
            vec![Url::parse("https://www.w3.org/ns/credentials/v2").unwrap()],
            vec!["VerifiableCredential".to_string()],
            Issuer::Url(Url::parse("https://example.com/issuer").unwrap()),
            serde_json::json!({ "id": "did:example:subject" }),
        )
        .valid_from(Utc::now() - Duration::hours(1))
        .valid_until(Utc::now() + Duration::hours(1))
        .build()
        .sign(&signing_key())
        .expect("Failed to sign VC");

        assert!(signed.verify(&verifying_key()).is_ok());
    }

    /// A `SchemaSource::Url` that cannot be fetched surfaces as `VcError::SchemaFetch`.
    /// Port 1 is reliably closed, so the connection fails without needing the network.
    #[test]
    fn schema_url_fetch_failure_is_schema_fetch_error() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        assert!(matches!(
            vc.validate(&SchemaSource::Url("http://127.0.0.1:1/schema.json")),
            Err(VcError::SchemaFetch(_))
        ));
    }

    #[test]
    fn validate_with_schema_check_true_positive() {
        let private_key = signing_key();
        let public_key = verifying_key();

        let vc: VerifiableCredential = serde_json::from_str::<UnsignedVerifiableCredential>(
            include_str!("test_data/verifiable_credentials/unsigned.json"),
        )
        .expect("Failed to deserialize JSON")
        .sign(&private_key)
        .expect("Failed to sign VC");

        let schema_str = include_str!("test_data/schemas/schema.json");
        let schema: serde_json::Value =
            serde_json::from_str(schema_str).expect("Failed to parse schema JSON");

        let verify_result = vc
            .validate(&SchemaSource::Inline(&schema))
            .and_then(|()| vc.verify(&public_key));

        assert!(verify_result.is_ok());
    }

    #[test]
    fn validate_with_schema_check_true_negative() {
        let private_key = signing_key();
        let public_key = verifying_key();

        let vc: VerifiableCredential = serde_json::from_str::<UnsignedVerifiableCredential>(
            include_str!("test_data/verifiable_credentials/unsigned.json"),
        )
        .expect("Failed to deserialize JSON")
        .sign(&private_key)
        .expect("Failed to sign VC");

        let schema_str = include_str!("test_data/schemas/schema_fail.json");
        let schema: serde_json::Value =
            serde_json::from_str(schema_str).expect("Failed to parse schema JSON");

        let verify_result = vc
            .validate(&SchemaSource::Inline(&schema))
            .and_then(|()| vc.verify(&public_key));

        assert!(matches!(verify_result, Err(VcError::SchemaMismatch)));
    }

    /// An Ed25519 key is rejected unless it is exactly 32 bytes.
    #[test]
    fn key_new_rejects_wrong_length() {
        assert!(matches!(
            SigningKey::new(Algorithm::Ed25519, &[0u8; 31]),
            Err(VcError::KeyDecode(_))
        ));
        assert!(matches!(
            SigningKey::new(Algorithm::Ed25519, &[0u8; 33]),
            Err(VcError::KeyDecode(_))
        ));
        assert!(matches!(
            VerifyingKey::new(Algorithm::Ed25519, &[0u8; 31]),
            Err(VcError::KeyDecode(_))
        ));
        // Exactly 32 bytes is accepted.
        assert!(SigningKey::new(Algorithm::Ed25519, &[7u8; 32]).is_ok());
        assert!(VerifyingKey::new(Algorithm::Ed25519, &[7u8; 32]).is_ok());
    }

    /// A well-formed signature verified against a different (valid) public key
    /// fails with SignatureVerificationFailed — distinct from the tampered-payload path.
    #[test]
    fn verify_rejects_wrong_public_key() {
        let signed_vc = serde_json::from_str::<UnsignedVerifiableCredential>(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON")
        .sign(&signing_key())
        .expect("Failed to sign VC");

        // A different, valid keypair: the signature is well-formed but won't match.
        let other = generate_keypair(Algorithm::Ed25519);
        assert!(matches!(
            signed_vc.verify(&other.verifying_key),
            Err(VcError::SignatureVerificationFailed)
        ));
    }

    /// A `proofValue` that isn't valid multibase fails at the decode step — a distinct
    /// error from a well-formed-but-wrong signature.
    #[test]
    fn verify_rejects_undecodable_proof_value() {
        let vc: VerifiableCredential = serde_json::from_value(serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "https://example.com/",
            "credentialSubject": { "id": "did:example:subject" },
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "proofPurpose": "assertionMethod",
                "proofValue": "not valid multibase !!!"
            }
        }))
        .expect("VC should deserialize");

        assert!(matches!(
            vc.verify(&verifying_key()),
            Err(VcError::ProofDecode(_))
        ));
    }

    /// A `proofValue` that decodes (valid multibase) but isn't a 64-byte Ed25519
    /// signature is rejected as malformed. `z` is the base58btc multibase prefix;
    /// "1111111111" decodes to ten zero bytes.
    #[test]
    fn verify_rejects_malformed_signature_length() {
        let vc: VerifiableCredential = serde_json::from_value(serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "https://example.com/",
            "credentialSubject": { "id": "did:example:subject" },
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "proofPurpose": "assertionMethod",
                "proofValue": "z1111111111"
            }
        }))
        .expect("VC should deserialize");

        assert!(matches!(
            vc.verify(&verifying_key()),
            Err(VcError::MalformedSignature(_))
        ));
    }

    /// Regression: `Holder::Url` must serialize as a bare string (untagged), not
    /// `{"Url": "..."}`, and round-trip.
    #[test]
    fn holder_url_serializes_untagged_and_round_trips() {
        let vp = VerifiablePresentation {
            context: vec![Url::parse("https://www.w3.org/ns/credentials/v2").unwrap()],
            id: None,
            presentation_type: vec!["VerifiablePresentation".to_string()],
            verifiable_credential: None,
            holder: Some(Holder::Url(
                Url::parse("https://example.com/holder").unwrap(),
            )),
        };

        let json = serde_json::to_string(&vp).unwrap();
        assert!(
            json.contains(r#""holder":"https://example.com/holder""#),
            "holder should be a bare string, got: {json}"
        );
        assert!(!json.contains(r#""Url""#), "holder should not be tagged");

        let back: VerifiablePresentation = serde_json::from_str(&json).unwrap();
        assert_eq!(vp, back);
    }

    /// `Holder::Object` + `#[serde(flatten)]` additional properties must serialize
    /// alongside `id` and round-trip (mirrors the issuer-object case).
    #[test]
    fn holder_object_flatten_round_trips() {
        use std::collections::HashMap;

        let mut extra = HashMap::new();
        extra.insert("name".to_string(), serde_json::json!("Acme Holder"));

        let vp = VerifiablePresentation {
            context: vec![Url::parse("https://www.w3.org/ns/credentials/v2").unwrap()],
            id: None,
            presentation_type: vec!["VerifiablePresentation".to_string()],
            verifiable_credential: None,
            holder: Some(Holder::Object(HolderObject {
                id: Url::parse("https://example.com/holder").unwrap(),
                additional_properties: Some(extra),
            })),
        };

        let json = serde_json::to_string(&vp).unwrap();
        assert!(json.contains(r#""name":"Acme Holder""#), "got: {json}");

        let back: VerifiablePresentation = serde_json::from_str(&json).unwrap();
        assert_eq!(vp, back);
    }

    /// The untagged `Issuer::Object` + `#[serde(flatten)]` additional properties
    /// must serialize alongside `id` and round-trip.
    #[test]
    fn issuer_object_flatten_round_trips() {
        use std::collections::HashMap;

        let mut extra = HashMap::new();
        extra.insert("name".to_string(), serde_json::json!("Acme Corp"));

        let vc = UnsignedVerifiableCredential::builder(
            vec![Url::parse("https://www.w3.org/ns/credentials/v2").unwrap()],
            vec!["VerifiableCredential".to_string()],
            Issuer::Object(IssuerObject {
                id: Url::parse("https://example.com/issuer").unwrap(),
                additional_properties: Some(extra),
            }),
            serde_json::json!({ "id": "urn:uuid:1" }),
        )
        .build();

        let json = serde_json::to_string(&vc).unwrap();
        assert!(json.contains(r#""name":"Acme Corp""#), "got: {json}");

        let back: UnsignedVerifiableCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(vc, back);
    }

    /// Canonicalization regression guard, across every algorithm. An issuer object
    /// carries its flattened extras in a `HashMap`, whose iteration order varies
    /// between instances; deserialization rebuilds that map in a generally different
    /// order than the signer used. Because `signing_payload` canonicalizes with JCS
    /// (RFC 8785, sorted keys), the signature is taken over an order-independent form,
    /// so a credential with *several* issuer properties still verifies after a
    /// serialize -> deserialize round-trip. Without canonicalization the verifier would
    /// re-serialize the keys in a different order and reject a valid credential — the
    /// single-property `issuer_object_flatten_round_trips` above cannot catch this, and
    /// neither would a sign/verify of the same in-memory object (its HashMap iterates
    /// identically both times). Exercises the full sign -> round-trip -> verify loop.
    #[test]
    fn multi_property_issuer_verifies_after_roundtrip_all_algorithms() {
        use std::collections::HashMap;

        // Enough distinct keys that an accidental order-match after the round-trip is
        // astronomically unlikely, so a reversion to non-canonical signing is caught.
        let extras = ["b", "a", "c", "e", "d", "z", "m", "q", "f", "t", "j", "k"];

        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::MlDsa44,
            Algorithm::MlDsa65,
            Algorithm::MlDsa87,
        ] {
            let (private_key, public_key) = generate_keypair_bytes(algorithm);

            let mut extra = HashMap::new();
            for (i, key) in extras.iter().enumerate() {
                extra.insert((*key).to_string(), serde_json::json!(i as i64));
            }

            let unsigned = UnsignedVerifiableCredential::builder(
                vec![Url::parse("https://www.w3.org/ns/credentials/v2").unwrap()],
                vec!["VerifiableCredential".to_string()],
                Issuer::Object(IssuerObject {
                    id: Url::parse("https://issuer.example.com/").unwrap(),
                    additional_properties: Some(extra),
                }),
                serde_json::json!({ "id": "did:example:subject" }),
            )
            .build();

            let signed = unsigned
                .sign_with_algorithm(algorithm, &private_key)
                .unwrap_or_else(|e| panic!("sign failed for {algorithm:?}: {e}"));

            // Round-trip through JSON: deserialization rebuilds the issuer's HashMap,
            // generally in a different iteration order than the signer's.
            let json = serde_json::to_string(&signed).unwrap();
            let reparsed: VerifiableCredential = serde_json::from_str(&json).unwrap();

            reparsed.verify_auto(&public_key).unwrap_or_else(|e| {
                panic!("verify_auto after round-trip failed for {algorithm:?}: {e}")
            });
            reparsed
                .verify_with_algorithm(algorithm, &public_key)
                .unwrap_or_else(|e| {
                    panic!("verify_with_algorithm after round-trip failed for {algorithm:?}: {e}")
                });
        }
    }

    /// A signed VC survives a JSON serialize -> deserialize round-trip unchanged.
    #[test]
    fn signed_vc_json_round_trips() {
        let signed = serde_json::from_str::<UnsignedVerifiableCredential>(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON")
        .sign(&signing_key())
        .expect("Failed to sign VC");

        let json = serde_json::to_string(&signed).unwrap();
        let back: VerifiableCredential = serde_json::from_str(&json).unwrap();

        assert_eq!(signed, back);
    }

    // --- Multi-algorithm signing (ML-DSA) -------------------------------------

    fn sample_unsigned() -> UnsignedVerifiableCredential {
        serde_json::from_value(serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "https://example.com/issuer",
            "credentialSubject": { "id": "did:example:subject", "n": 42 }
        }))
        .expect("sample VC should deserialize")
    }

    /// Generated keypair → sign_with_algorithm → verify_with_algorithm and verify_auto,
    /// for every supported algorithm including the three ML-DSA parameter sets.
    #[test]
    fn sign_verify_roundtrip_all_algorithms() {
        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::MlDsa44,
            Algorithm::MlDsa65,
            Algorithm::MlDsa87,
        ] {
            let (private_key, public_key) = generate_keypair_bytes(algorithm);

            let signed = sample_unsigned()
                .sign_with_algorithm(algorithm, &private_key)
                .unwrap_or_else(|e| panic!("sign failed for {algorithm:?}: {e}"));

            // The proof records the algorithm's cryptosuite.
            assert_eq!(
                serde_json::to_value(&signed).unwrap()["proof"]["cryptosuite"],
                algorithm.cryptosuite()
            );

            // Explicit-algorithm verify and cryptosuite-dispatched verify both pass.
            signed
                .verify_with_algorithm(algorithm, &public_key)
                .unwrap_or_else(|e| panic!("verify_with_algorithm failed for {algorithm:?}: {e}"));
            signed
                .verify_auto(&public_key)
                .unwrap_or_else(|e| panic!("verify_auto failed for {algorithm:?}: {e}"));
        }
    }

    /// The injection path: take the canonical `signing_payload`, sign it "externally"
    /// (here: with ML-DSA-65), then wrap the signature with `Proof::new_data_integrity` +
    /// `set_proof_value` + `VerifiableCredential::from_parts`, and verify. This is what
    /// unblocks signing with an algorithm computed outside the crate.
    #[test]
    fn external_proof_injection_roundtrip() {
        let (private_key, public_key) = generate_keypair_bytes(Algorithm::MlDsa65);
        let unsigned = sample_unsigned();

        // Stand-in for an external signer: produce the proofValue over signing_payload.
        let proof_value = unsigned
            .clone()
            .sign_with_algorithm(Algorithm::MlDsa65, &private_key)
            .expect("sign")
            .proof
            .proof_value()
            .to_string();

        // Inject it into a hand-built proof and assemble the credential.
        let proof = Proof::new_data_integrity(Algorithm::MlDsa65.cryptosuite(), String::new())
            .set_proof_value(proof_value);
        let injected = VerifiableCredential::from_parts(unsigned, proof);

        injected
            .verify_auto(&public_key)
            .expect("injected ML-DSA proof should verify");
    }

    /// A signature made under one algorithm must not verify under another.
    #[test]
    fn cross_algorithm_verification_fails() {
        let (sk_44, _) = generate_keypair_bytes(Algorithm::MlDsa44);
        let (_, pk_65) = generate_keypair_bytes(Algorithm::MlDsa65);

        let signed = sample_unsigned()
            .sign_with_algorithm(Algorithm::MlDsa44, &sk_44)
            .expect("sign");

        // Wrong parameter set / key: must error, not falsely verify.
        assert!(signed
            .verify_with_algorithm(Algorithm::MlDsa65, &pk_65)
            .is_err());
    }

    /// A tampered credential signed with ML-DSA fails verification (the signature covers
    /// the canonical content).
    #[test]
    fn mldsa_verify_rejects_tampered_payload() {
        let (private_key, public_key) = generate_keypair_bytes(Algorithm::MlDsa65);
        let signed = sample_unsigned()
            .sign_with_algorithm(Algorithm::MlDsa65, &private_key)
            .expect("sign");

        // Flip a value in the subject after signing.
        let mut json = serde_json::to_value(&signed).unwrap();
        json["credentialSubject"]["n"] = serde_json::json!(999);
        let tampered: VerifiableCredential =
            serde_json::from_value(json).expect("tampered VC still deserializes");

        assert!(matches!(
            tampered.verify_auto(&public_key),
            Err(VcError::SignatureVerificationFailed)
        ));
    }

    /// `verify_auto` rejects a proof whose cryptosuite the toolkit doesn't implement.
    #[test]
    fn verify_auto_rejects_unknown_cryptosuite() {
        let (private_key, public_key) = generate_keypair_bytes(Algorithm::MlDsa65);
        let mut signed = sample_unsigned()
            .sign_with_algorithm(Algorithm::MlDsa65, &private_key)
            .expect("sign");
        signed.proof = signed.proof.set_crypto_suite("bbs-2023".to_string());

        assert!(matches!(
            signed.verify_auto(&public_key),
            Err(VcError::UnsupportedCryptosuite(suite)) if suite == "bbs-2023"
        ));
    }

    /// The Ed25519-typed `verify` must refuse a credential whose proof names a non-Ed25519
    /// cryptosuite (e.g. ML-DSA), rather than silently trying to read 32-byte Ed25519 keys
    /// out of an ML-DSA proof. This is the distinguishing branch of `verify` vs
    /// `verify_with_algorithm` (which trusts the caller's algorithm).
    #[test]
    fn ed25519_verify_rejects_mldsa_cryptosuite() {
        let (private_key, _) = generate_keypair_bytes(Algorithm::MlDsa65);
        let signed = sample_unsigned()
            .sign_with_algorithm(Algorithm::MlDsa65, &private_key)
            .expect("sign");

        // `verify` is Ed25519-only; the ML-DSA cryptosuite must be rejected up front.
        assert!(matches!(
            signed.verify(&verifying_key()),
            Err(VcError::UnsupportedCryptosuite(suite)) if suite == "mldsa65-jcs-2025"
        ));
    }

    /// `generate_keypair_bytes` must emit keys of exactly the FIPS 204 / Ed25519 lengths the
    /// bilateral wire contract pins (see ML_DSA_NOTES.md). A drift here silently breaks
    /// interop with partners, so lock the sizes in a test.
    #[test]
    fn keypair_byte_lengths_match_wire_contract() {
        for (algorithm, private_len, public_len) in [
            (Algorithm::Ed25519, 32, 32),
            (Algorithm::MlDsa44, 2560, 1312),
            (Algorithm::MlDsa65, 4032, 1952),
            (Algorithm::MlDsa87, 4896, 2592),
        ] {
            let (private_key, public_key) = generate_keypair_bytes(algorithm);
            assert_eq!(
                private_key.len(),
                private_len,
                "{algorithm:?} private key length"
            );
            assert_eq!(
                public_key.len(),
                public_len,
                "{algorithm:?} public key length"
            );
        }
    }

    /// ML-DSA signing is hedged (FIPS 204 randomized variant), so signing the same payload
    /// twice yields different `proofValue`s — and both must still verify. Guards against a
    /// regression to deterministic signing.
    #[test]
    fn mldsa_signing_is_hedged_and_nondeterministic() {
        let (private_key, public_key) = generate_keypair_bytes(Algorithm::MlDsa65);

        let first = sample_unsigned()
            .sign_with_algorithm(Algorithm::MlDsa65, &private_key)
            .expect("first sign");
        let second = sample_unsigned()
            .sign_with_algorithm(Algorithm::MlDsa65, &private_key)
            .expect("second sign");

        assert_ne!(
            first.proof.proof_value(),
            second.proof.proof_value(),
            "hedged ML-DSA signatures over the same payload must differ"
        );
        first.verify_auto(&public_key).expect("first verifies");
        second.verify_auto(&public_key).expect("second verifies");
    }

    /// A wrong-length ML-DSA signing key must surface as a typed `KeyDecode` error, not a
    /// panic — the FIPS 204 expanded-key loader can panic on malformed bytes, and signing
    /// guards against that since keys are caller-supplied (see ML_DSA_NOTES.md §3).
    #[test]
    fn mldsa_sign_rejects_wrong_length_key_without_panicking() {
        for bad_key in [vec![0u8; 16], vec![0u8; 4031], vec![7u8; 5000]] {
            assert!(matches!(
                sample_unsigned().sign_with_algorithm(Algorithm::MlDsa65, &bad_key),
                Err(VcError::KeyDecode(_))
            ));
        }
    }

    /// A wrong-length ML-DSA public key is rejected at verification with `InvalidPublicKey`,
    /// distinct from a well-formed-but-wrong key (which fails as `SignatureVerificationFailed`).
    #[test]
    fn mldsa_verify_rejects_wrong_length_public_key() {
        let (private_key, _) = generate_keypair_bytes(Algorithm::MlDsa65);
        let signed = sample_unsigned()
            .sign_with_algorithm(Algorithm::MlDsa65, &private_key)
            .expect("sign");

        assert!(matches!(
            signed.verify_with_algorithm(Algorithm::MlDsa65, &[0u8; 100]),
            Err(VcError::InvalidPublicKey(_))
        ));
    }

    /// A well-formed ML-DSA signature verified against a different (valid) key of the same
    /// parameter set fails as `SignatureVerificationFailed` — the ML-DSA analogue of
    /// [verify_rejects_wrong_public_key].
    #[test]
    fn mldsa_verify_rejects_wrong_key_same_param_set() {
        let (private_key, _) = generate_keypair_bytes(Algorithm::MlDsa65);
        let (_, other_public_key) = generate_keypair_bytes(Algorithm::MlDsa65);

        let signed = sample_unsigned()
            .sign_with_algorithm(Algorithm::MlDsa65, &private_key)
            .expect("sign");

        assert!(matches!(
            signed.verify_auto(&other_public_key),
            Err(VcError::SignatureVerificationFailed)
        ));
    }

    /// Round-trips every `Algorithm` through its `cryptosuite` string and back, pinning the
    /// provisional ML-DSA identifiers and ensuring the two mappings stay mutually inverse.
    #[test]
    fn algorithm_cryptosuite_round_trips() {
        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::MlDsa44,
            Algorithm::MlDsa65,
            Algorithm::MlDsa87,
        ] {
            assert_eq!(
                Algorithm::from_cryptosuite(algorithm.cryptosuite()),
                Some(algorithm)
            );
        }
        assert_eq!(Algorithm::from_cryptosuite("not-a-real-suite"), None);
    }

    // --- Typed keys -----------------------------------------------------------

    /// The typed-key path: `generate_keypair` → `sign` → `verify` for every ML-DSA
    /// parameter set. The algorithm rides along with the key, so no separate `Algorithm`
    /// argument is threaded through — the same `sign`/`verify` used for Ed25519.
    #[test]
    fn typed_keys_sign_and_verify() {
        for algorithm in [Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::MlDsa87] {
            let keypair = generate_keypair(algorithm);
            assert_eq!(keypair.signing_key.algorithm(), algorithm);

            let signed = sample_unsigned()
                .sign(&keypair.signing_key)
                .unwrap_or_else(|e| panic!("sign failed for {algorithm:?}: {e}"));
            signed
                .verify(&keypair.verifying_key)
                .unwrap_or_else(|e| panic!("verify failed for {algorithm:?}: {e}"));
        }
    }

    /// The key constructors length-check against the algorithm, so a wrong-length buffer is
    /// rejected up front rather than at sign/verify time.
    #[test]
    fn typed_keys_reject_wrong_length() {
        // ML-DSA-65 signing key is 4032 bytes, verifying key 1952.
        assert!(matches!(
            SigningKey::new(Algorithm::MlDsa65, &[0u8; 4031]),
            Err(VcError::KeyDecode(_))
        ));
        assert!(matches!(
            VerifyingKey::new(Algorithm::MlDsa65, &[0u8; 1953]),
            Err(VcError::KeyDecode(_))
        ));
        // A verifying-key-sized buffer is still wrong for a signing key.
        assert!(matches!(
            SigningKey::new(Algorithm::MlDsa65, &[0u8; 1952]),
            Err(VcError::KeyDecode(_))
        ));
    }

    /// `verify` pins the proof's cryptosuite to the key's parameter set: a credential signed
    /// with ML-DSA-44 must not verify under an ML-DSA-87 key (even though both are valid
    /// keys), surfacing as `UnsupportedCryptosuite`.
    #[test]
    fn verify_rejects_mismatched_param_set() {
        let kp_44 = generate_keypair(Algorithm::MlDsa44);
        let kp_87 = generate_keypair(Algorithm::MlDsa87);

        let signed = sample_unsigned()
            .sign(&kp_44.signing_key)
            .expect("sign with ML-DSA-44");

        assert!(matches!(
            signed.verify(&kp_87.verifying_key),
            Err(VcError::UnsupportedCryptosuite(suite)) if suite == "mldsa44-jcs-2025"
        ));
    }

    /// The signing key's `Debug` must not leak the secret bytes.
    #[test]
    fn signing_key_debug_is_redacted() {
        let keypair = generate_keypair(Algorithm::MlDsa65);
        let debug = format!("{:?}", keypair.signing_key);
        assert!(debug.contains("REDACTED"), "got: {debug}");
        // A run of the raw key bytes must not appear in the Debug output.
        let raw = format!("{:?}", keypair.signing_key.as_bytes());
        assert!(!debug.contains(&raw));
    }

    /// A `DataIntegrityProof` with no `cryptosuite` is rejected rather than assumed to be
    /// Ed25519 — by both the Ed25519-typed `verify` and `verify_auto`.
    #[test]
    fn verify_rejects_missing_cryptosuite() {
        let vc: VerifiableCredential = serde_json::from_value(serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "https://example.com/",
            "credentialSubject": { "id": "did:example:subject" },
            "proof": {
                "type": "DataIntegrityProof",
                "proofPurpose": "assertionMethod",
                "proofValue": "z111" // never reached; cryptosuite check fails first
            }
        }))
        .expect("VC without cryptosuite should still deserialize");

        assert!(matches!(
            vc.verify(&verifying_key()),
            Err(VcError::MissingCryptosuite)
        ));
        assert!(matches!(
            vc.verify_auto(&[0u8; 32]),
            Err(VcError::MissingCryptosuite)
        ));
    }
}
