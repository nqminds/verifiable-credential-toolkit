#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use chrono::{DateTime, Duration, Utc};
    use url::Url;
    use verifiable_credential_toolkit::{
        UnsignedVerifiableCredential, VerifiableCredential, VerifiablePresentation,
    };

    /// Test that a valid Verifiable Credential can be deserialized
    #[test]
    fn valid_vc_deserializes() {
        let vc: VerifiableCredential =
            serde_json::from_str(include_str!("test_data/verifiable_credentials/vc.json"))
                .expect("Failed to deserialize JSON");

        assert!(serde_json::to_string(&vc).is_ok());
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

        let private_key: &[u8] = &std::fs::read("tests/test_data/keys/key.priv")
            .expect("Error reading private key from file");

        let signed_vc = vc.sign(private_key).unwrap();

        assert!(serde_json::to_string(&signed_vc).is_ok());
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

        let private_key: &[u8] = &std::fs::read("tests/test_data/keys/key.priv")
            .expect("Error reading private key from file");

        let signed_vc = vc.sign(private_key).expect("Failed to sign VC");

        let signed_vc_2 = vc_2.sign(private_key).expect("Failed to sign VC");

        assert_eq!(signed_vc, signed_vc_2);
    }

    #[test]
    fn sign_with_schema_check() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key: &[u8] = &std::fs::read("tests/test_data/keys/key.priv")
            .expect("Error reading private key from file");

        let schema = include_str!("test_data/schemas/schema.json");

        let signed_vc = vc
            .sign_with_schema_check(private_key, schema)
            .expect("Failed to sign VC");

        assert!(serde_json::to_string(&signed_vc).is_ok());
    }

    #[test]
    fn sign_with_schema_check_fail() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key: &[u8] = &std::fs::read("tests/test_data/keys/key.priv")
            .expect("Error reading private key from file");

        let schema = include_str!("test_data/schemas/schema_fail.json");

        let signed_vc = vc.sign_with_schema_check(private_key, schema);

        assert!(signed_vc.is_err());
    }

    #[test]
    fn signed_to_unsigned() {
        let private_key: &[u8] = &std::fs::read("tests/test_data/keys/key.priv")
            .expect("Error reading private key from file");

        let vc: VerifiableCredential = serde_json::from_str::<UnsignedVerifiableCredential>(
            include_str!("test_data/verifiable_credentials/unsigned.json"),
        )
        .expect("Failed to deserialize JSON")
        .sign(private_key)
        .expect("Failed to sign VC");

        let clone_vc = vc.clone();
        let mut unsigned_vc = clone_vc.to_unsigned();

        // Set id of unsigned_vc
        unsigned_vc.id =
            Some(Url::parse("http://example.com/credentials/3732").expect("Invalid URL"));

        let new_signed_vc = unsigned_vc.sign(private_key).expect("Failed to sign VC");

        println!("{}", serde_json::to_string_pretty(&vc).unwrap());
        println!("{}", serde_json::to_string_pretty(&new_signed_vc).unwrap());

        assert_ne!(vc, new_signed_vc);
    }

    #[test]
    fn sign_with_schema_check_url() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key: &[u8] = &std::fs::read("tests/test_data/keys/key.priv")
            .expect("Error reading private key from file");

        let signed_vc = vc
            .sign_with_schema_check_from_url(private_key, "https://json.schemastore.org/any.json")
            .expect("Failed to sign VC");

        assert!(serde_json::to_string(&signed_vc).is_ok());
    }

    #[test]
    fn sign_with_schema_check_url_fails() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key: &[u8] = &std::fs::read("tests/test_data/keys/key.priv")
            .expect("Error reading private key from file");

        let signed_vc = vc.sign_with_schema_check_from_url(
            private_key,
            "http://localhost:8000/DoesNotExist.json",
        );

        assert!(signed_vc.is_err());
    }

    #[test]
    fn customise_proof_using_builder() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key: &[u8] = &std::fs::read("tests/test_data/keys/key.priv")
            .expect("Error reading private key from file");

        let mut signed_vc = vc.sign(private_key).unwrap();

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

        let private_key: &[u8] = &std::fs::read("tests/test_data/keys/key.priv")
            .expect("Error reading private key from file");

        let mut signed_vc = vc.sign(private_key).unwrap();

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
        let private_key: &[u8] = &std::fs::read("tests/test_data/keys/key.priv")
            .expect("Error reading private key from file");

        let vc: VerifiableCredential = serde_json::from_str::<UnsignedVerifiableCredential>(
            include_str!("test_data/verifiable_credentials/unsigned.json"),
        )
        .expect("Failed to deserialize JSON")
        .sign(private_key)
        .expect("Failed to sign VC");

        let public_key = std::fs::read("tests/test_data/keys/key.pub")
            .expect("Error reading public key from file");

        let verify_result = vc.verify(&public_key);

        match &verify_result {
            Ok(_) => println!("Verification successful"),
            Err(e) => println!("Verification failed: {:?}", e),
        }
        assert!(verify_result.is_ok());
    }

    #[test]
    fn verify_denies_modified_verifiable_credential() {
        let private_key: &[u8] = &std::fs::read("tests/test_data/keys/key.priv")
            .expect("Error reading private key from file");

        let vc: VerifiableCredential = serde_json::from_str::<UnsignedVerifiableCredential>(
            include_str!("test_data/verifiable_credentials/unsigned.json"),
        )
        .expect("Failed to deserialize JSON")
        .sign(private_key)
        .expect("Failed to sign VC");

        let mut vc_serialized = serde_json::to_string(&vc).expect("Failed to serialize VC");

        vc_serialized = vc_serialized.replace("HenryTrustPhone", "AshEvilPhone");

        let edited_vc: VerifiableCredential =
            serde_json::from_str(&vc_serialized).expect("Failed to deserialize JSON");

        let public_key = std::fs::read("tests/test_data/keys/key.pub")
            .expect("Error reading public key from file");

        let verify_result = edited_vc.verify(&public_key);

        assert!(verify_result.is_err());
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
        let private_key = std::fs::read("tests/test_data/keys/key.priv")
            .expect("Error reading private key from file");
        let public_key = std::fs::read("tests/test_data/keys/key.pub")
            .expect("Error reading public key from file");

        let signed_vc = serde_json::from_str::<UnsignedVerifiableCredential>(include_str!(
            "test_data/verifiable_credentials/unsigned_validFrom_invalid.json"
        ))
        .expect("Failed to deserialize JSON")
        .sign(&private_key)
        .expect("Failed to sign VC");

        let verify_result = signed_vc.verify(&public_key);

        assert!(verify_result.is_err());
    }

    #[test]
    fn valid_until_verification_true_negative() {
        let private_key = std::fs::read("tests/test_data/keys/key.priv")
            .expect("Error reading private key from file");
        let public_key = std::fs::read("tests/test_data/keys/key.pub")
            .expect("Error reading public key from file");

        let signed_vc = serde_json::from_str::<UnsignedVerifiableCredential>(include_str!(
            "test_data/verifiable_credentials/unsigned_validUntil_invalid.json"
        ))
        .expect("Failed to deserialize JSON")
        .sign(&private_key)
        .expect("Failed to sign VC");

        let verify_result = signed_vc.verify(&public_key);

        assert!(verify_result.is_err());
    }

    #[test]
    fn valid_from_verification_true_positive() {
        let private_key = std::fs::read("tests/test_data/keys/key.priv")
            .expect("Error reading private key from file");
        let public_key = std::fs::read("tests/test_data/keys/key.pub")
            .expect("Error reading public key from file");

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
        let private_key = std::fs::read("tests/test_data/keys/key.priv")
            .expect("Error reading private key from file");
        let public_key = std::fs::read("tests/test_data/keys/key.pub")
            .expect("Error reading public key from file");

        let signed_vc = serde_json::from_str::<UnsignedVerifiableCredential>(include_str!(
            "test_data/verifiable_credentials/unsigned_validUntil_valid.json"
        ))
        .expect("Failed to deserialize JSON")
        .sign(&private_key)
        .expect("Failed to sign VC");

        let verify_result = signed_vc.verify(&public_key);

        assert!(verify_result.is_ok());
    }

    #[test]
    fn validate_with_schema_check_true_positive() {
        let private_key: &[u8] = &std::fs::read("tests/test_data/keys/key.priv")
            .expect("Error reading private key from file");
        let public_key = std::fs::read("tests/test_data/keys/key.pub")
            .expect("Error reading public key from file");

        let vc: VerifiableCredential = serde_json::from_str::<UnsignedVerifiableCredential>(
            include_str!("test_data/verifiable_credentials/unsigned.json"),
        )
        .expect("Failed to deserialize JSON")
        .sign(private_key)
        .expect("Failed to sign VC");

        let schema = include_str!("test_data/schemas/schema.json");

        let verify_result = vc.verify_with_schema_check(&public_key, schema);

        assert!(verify_result.is_ok());
    }

    #[test]
    fn validate_with_schema_check_true_negative() {
        let private_key: &[u8] = &std::fs::read("tests/test_data/keys/key.priv")
            .expect("Error reading private key from file");
        let public_key = std::fs::read("tests/test_data/keys/key.pub")
            .expect("Error reading public key from file");

        let vc: VerifiableCredential = serde_json::from_str::<UnsignedVerifiableCredential>(
            include_str!("test_data/verifiable_credentials/unsigned.json"),
        )
        .expect("Failed to deserialize JSON")
        .sign(private_key)
        .expect("Failed to sign VC");

        let schema = include_str!("test_data/schemas/schema_fail.json");

        let verify_result = vc.verify_with_schema_check(&public_key, schema);

        assert!(verify_result.is_err());
    }
}
