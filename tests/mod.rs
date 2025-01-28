#[cfg(test)]
mod tests {
    use verifiable_credential_toolkit::{UnsignedVerifiableCredential, VerifiableCredential};

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
            "test_data/verifiable_credentials/unsigned_one_or_many.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key = std::fs::read("tests/test_data/keys/private_key.pkcs8")
            .expect("Error reading private key from file");

        let signed_vc = vc.sign(&private_key).unwrap();

        assert!(serde_json::to_string(&signed_vc).is_ok());
    }

    /// Test that two UnsignedVerifiableCredential of equal values but different ordering produce the same signed VerifiableCredential
    #[test]
    fn canonicalisation_sign() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned_one_or_many.json"
        ))
        .expect("Failed to deserialize JSON");

        let vc_2: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/canonicalization.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key = std::fs::read("tests/test_data/keys/private_key.pkcs8")
            .expect("Error reading private key from file");

        let signed_vc = vc.sign(&private_key).expect("Failed to sign VC");

        let signed_vc_2 = vc_2.sign(&private_key).expect("Failed to sign VC");

        assert_eq!(signed_vc, signed_vc_2);
    }

    #[test]
    fn sign_with_schema_check() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned_one_or_many.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key = std::fs::read("tests/test_data/keys/private_key.pkcs8")
            .expect("Error reading private key from file");

        let schema = include_str!("test_data/schemas/schema.json");

        let signed_vc = vc
            .sign_with_schema_check(&private_key, schema)
            .expect("Failed to sign VC");

        assert!(serde_json::to_string(&signed_vc).is_ok());
    }

    #[test]
    fn sign_with_schema_check_fail() {
        let vc: UnsignedVerifiableCredential = serde_json::from_str(include_str!(
            "test_data/verifiable_credentials/unsigned_one_or_many.json"
        ))
        .expect("Failed to deserialize JSON");

        let private_key = std::fs::read("tests/test_data/keys/private_key.pkcs8")
            .expect("Error reading private key from file");

        let schema = include_str!("test_data/schemas/schema_fail.json");

        let signed_vc = vc.sign_with_schema_check(&private_key, schema);

        assert!(signed_vc.is_err());
    }

    #[test]
    fn signed_to_unsigned() {
        let private_key = std::fs::read("tests/test_data/keys/private_key.pkcs8")
            .expect("Error reading private key from file");

        let vc: VerifiableCredential = serde_json::from_str::<UnsignedVerifiableCredential>(
            include_str!("test_data/verifiable_credentials/unsigned_one_or_many.json"),
        )
        .expect("Failed to deserialize JSON")
        .sign(&private_key)
        .expect("Failed to sign VC");

        let clone_vc = vc.clone();
        let mut unsigned_vc = clone_vc.to_unsigned();

        // Set id of unsigned_vc
        unsigned_vc.id = Some("http://example.com/credentials/3732".to_string());

        let new_signed_vc = unsigned_vc.sign(&private_key).expect("Failed to sign VC");

        println!("{}", serde_json::to_string_pretty(&vc).unwrap());
        println!("{}", serde_json::to_string_pretty(&new_signed_vc).unwrap());

        assert_ne!(vc, new_signed_vc);
    }
}
