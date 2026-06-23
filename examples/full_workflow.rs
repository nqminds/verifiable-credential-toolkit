//! End-to-end example: generate keys, create a credential, sign it, verify it,
//! and inspect the output.
//!
//! Run with:
//!   cargo run --example full_workflow

use url::Url;
use verifiable_credential_toolkit::{
    generate_keypair, UnsignedVerifiableCredential, VerifiableCredential, VerifiablePresentation,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Step 1: Generate an Ed25519 keypair ─────────────────────────────
    println!("=== Step 1: Generate Ed25519 keypair ===\n");
    let keypair = generate_keypair();
    let signing_key = keypair.signing_key;
    let verifying_key = keypair.verifying_key;
    println!(
        "Public key (32 bytes): {:?}\n",
        &verifying_key.to_bytes()[..8]
    );

    // ── Step 2: Define an unsigned Verifiable Credential ────────────────
    println!("=== Step 2: Create an unsigned Verifiable Credential ===\n");
    let unsigned_vc_json = r#"{
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "urn:uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "type": ["VerifiableCredential", "DeviceCertificate"],
        "issuer": "https://example.com/issuers/sensor-manufacturer",
        "validFrom": "2024-01-01T00:00:00Z",
        "validUntil": "2030-12-31T23:59:59Z",
        "credentialSubject": {
            "id": "urn:uuid:device-001",
            "name": "Temperature Sensor Alpha",
            "model": "TS-3000",
            "location": "Building A, Floor 2"
        }
    }"#;

    let unsigned_vc: UnsignedVerifiableCredential = serde_json::from_str(unsigned_vc_json)?;
    println!("Credential type: {:?}", unsigned_vc.credential_type);
    println!("Issuer: {:?}", unsigned_vc.issuer);
    println!("Subject: {}\n", unsigned_vc.credential_subject);

    // ── Step 3: Sign the credential ─────────────────────────────────────
    println!("=== Step 3: Sign the credential ===\n");
    let signed_vc: VerifiableCredential = unsigned_vc.sign(&signing_key)?;
    println!("Proof type: {}", signed_vc.proof.proof_type);
    println!("Proof purpose: {}", signed_vc.proof.proof_purpose);
    println!(
        "Signed credential JSON:\n{}\n",
        serde_json::to_string_pretty(&signed_vc)?
    );

    // ── Step 4: Verify the credential ───────────────────────────────────
    println!("=== Step 4: Verify the credential ===\n");
    match signed_vc.verify(&verifying_key) {
        Ok(()) => println!("✓ Credential signature is valid!"),
        Err(e) => println!("✗ Verification failed: {}", e),
    }

    // ── Step 5: Demonstrate tamper detection ────────────────────────────
    println!("\n=== Step 5: Tamper detection ===\n");
    let mut tampered_json = serde_json::to_string(&signed_vc)?;
    tampered_json = tampered_json.replace("Temperature Sensor Alpha", "TAMPERED NAME");
    let tampered_vc: VerifiableCredential = serde_json::from_str(&tampered_json)?;

    match tampered_vc.verify(&verifying_key) {
        Ok(()) => println!("✗ Tampered credential was accepted (unexpected!)"),
        Err(e) => println!("✓ Tampered credential correctly rejected: {}", e),
    }

    // ── Step 6: Bundle into a Verifiable Presentation ───────────────────
    println!("\n=== Step 6: Create a Verifiable Presentation ===\n");
    let vp = VerifiablePresentation {
        context: vec![Url::parse("https://www.w3.org/ns/credentials/v2")?],
        id: Some(Url::parse("urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5")?),
        presentation_type: vec!["VerifiablePresentation".to_string()],
        verifiable_credential: Some(vec![signed_vc]),
        holder: None,
    };
    println!(
        "Presentation JSON:\n{}\n",
        serde_json::to_string_pretty(&vp)?
    );

    println!("=== Done! ===");
    Ok(())
}
