#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use chrono::{DateTime, Duration, Utc};
    use url::Url;
    use verifiable_credential_toolkit::{
        generate_keypair, Holder, HolderObject, Issuer, IssuerObject, SchemaSource, SigningKey,
        UnsignedVerifiableCredential, VcError, VerifiableCredential, VerifiablePresentation,
        VerifyingKey,
    };

    /// Load the test signing key from disk.
    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(
            &std::fs::read("tests/test_data/keys/key.priv").expect("read private key"),
        )
        .expect("valid private key")
    }

    /// Load the test verifying key from disk.
    fn verifying_key() -> VerifyingKey {
        VerifyingKey::from_bytes(
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
            Err(VcError::SignatureVerificationFailed(_))
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

    /// Key newtypes reject anything that isn't exactly 32 bytes.
    #[test]
    fn key_from_bytes_rejects_wrong_length() {
        assert!(matches!(
            SigningKey::from_bytes(&[0u8; 31]),
            Err(VcError::InvalidPrivateKeyLength)
        ));
        assert!(matches!(
            SigningKey::from_bytes(&[0u8; 33]),
            Err(VcError::InvalidPrivateKeyLength)
        ));
        assert!(matches!(
            VerifyingKey::from_bytes(&[0u8; 31]),
            Err(VcError::InvalidPublicKeyLength)
        ));
        // Exactly 32 bytes is accepted.
        assert!(SigningKey::from_bytes(&[7u8; 32]).is_ok());
        assert!(VerifyingKey::from_bytes(&[7u8; 32]).is_ok());
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
        let other = generate_keypair();
        assert!(matches!(
            signed_vc.verify(&other.verifying_key),
            Err(VcError::SignatureVerificationFailed(_))
        ));
    }

    /// A `proofValue` that isn't valid base64 fails at the decode step — a distinct error
    /// from a well-formed-but-wrong signature.
    #[test]
    fn verify_rejects_non_base64_proof_value() {
        let vc: VerifiableCredential = serde_json::from_value(serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "https://example.com/",
            "credentialSubject": { "id": "did:example:subject" },
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "proofPurpose": "assertionMethod",
                "proofValue": "not valid base64 !!!"
            }
        }))
        .expect("VC should deserialize");

        assert!(matches!(
            vc.verify(&verifying_key()),
            Err(VcError::ProofDecode(_))
        ));
    }

    /// A `proofValue` that decodes but isn't a 64-byte Ed25519 signature is rejected as
    /// malformed, before any verification maths.
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
                "proofValue": "AAAA"
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
}
