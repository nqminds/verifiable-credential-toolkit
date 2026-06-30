//! Example: Sign and verify a credential with JSON Schema validation.
//!
//! This demonstrates how to enforce a specific structure on the
//! `credentialSubject` field using a JSON Schema. This is useful when
//! multiple organisations agree on what fields a credential must contain.
//!
//! Run with:
//!   cargo run --example schema_validation

use verifiable_credential_toolkit::{
    generate_keypair, Algorithm, SchemaSource, UnsignedVerifiableCredential,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = generate_keypair(Algorithm::Ed25519);
    let signing_key = keypair.signing_key;
    let verifying_key = keypair.verifying_key;

    // ── Define a JSON Schema for device credentials ─────────────────────
    // This schema requires "id" and "name" fields, and optionally accepts "model".
    let schema: serde_json::Value = serde_json::from_str(
        r#"{
        "title": "Device",
        "description": "Schema for a device credential subject",
        "type": "object",
        "properties": {
            "id": {
                "type": "string",
                "description": "Unique device identifier"
            },
            "name": {
                "type": "string",
                "description": "Human-readable device name"
            },
            "model": {
                "type": "string",
                "description": "Device model number"
            }
        },
        "required": ["id", "name"]
    }"#,
    )?;

    // ── Example 1: Valid credential (matches schema) ────────────────────
    println!("=== Example 1: Valid credential subject ===\n");
    let valid_vc: UnsignedVerifiableCredential = serde_json::from_str(
        r#"{
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": "https://example.com/issuers/device-manufacturer",
        "credentialSubject": {
            "id": "urn:uuid:device-001",
            "name": "Temperature Sensor A",
            "model": "TS-3000"
        }
    }"#,
    )?;

    match valid_vc
        .validate(&SchemaSource::Inline(&schema))
        .and_then(|()| valid_vc.sign(&signing_key))
    {
        Ok(signed) => {
            println!("✓ Signing succeeded (credential subject matches schema)");

            // Verify with schema check too
            match signed
                .validate(&SchemaSource::Inline(&schema))
                .and_then(|()| signed.verify(&verifying_key))
            {
                Ok(()) => println!("✓ Verification with schema check passed\n"),
                Err(e) => println!("✗ Verification failed: {}\n", e),
            }
        }
        Err(e) => println!("✗ Signing failed: {}\n", e),
    }

    // ── Example 2: Invalid credential (missing required "name" field) ───
    println!("=== Example 2: Invalid credential subject (missing 'name') ===\n");
    let invalid_vc: UnsignedVerifiableCredential = serde_json::from_str(
        r#"{
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": "https://example.com/issuers/device-manufacturer",
        "credentialSubject": {
            "id": "urn:uuid:device-002"
        }
    }"#,
    )?;

    match invalid_vc
        .validate(&SchemaSource::Inline(&schema))
        .and_then(|()| invalid_vc.sign(&signing_key))
    {
        Ok(_) => println!("✗ Signing succeeded unexpectedly"),
        Err(e) => println!("✓ Signing correctly rejected: {}\n", e),
    }

    // ── Example 3: Wrong field type ─────────────────────────────────────
    println!("=== Example 3: Wrong field type (name is a number) ===\n");
    let wrong_type_vc: UnsignedVerifiableCredential = serde_json::from_str(
        r#"{
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": "https://example.com/issuers/device-manufacturer",
        "credentialSubject": {
            "id": "urn:uuid:device-003",
            "name": 12345
        }
    }"#,
    )?;

    match wrong_type_vc
        .validate(&SchemaSource::Inline(&schema))
        .and_then(|()| wrong_type_vc.sign(&signing_key))
    {
        Ok(_) => println!("✗ Signing succeeded unexpectedly"),
        Err(e) => println!("✓ Signing correctly rejected: {}\n", e),
    }

    println!("=== Done! ===");
    Ok(())
}
