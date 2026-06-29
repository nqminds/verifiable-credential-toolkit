//! Post-quantum (ML-DSA) signing across every algorithm, wire format, and verification
//! path the toolkit exposes — the parts the Ed25519 `full_workflow` example doesn't reach.
//!
//! Demonstrates:
//!   1. Generating raw ML-DSA key pairs and signing with `sign_with_algorithm`.
//!   2. The three verification entry points: `verify_auto`, `verify_with_algorithm`.
//!   3. Cross-format interop — a credential signed once verifies as JSON, CBOR, and
//!      Protobuf, because the signature is over the format-independent JCS canonical form.
//!   4. Signing/verifying directly on CBOR and Protobuf bytes via the `CredentialCodec` trait.
//!   5. Injecting an externally-computed signature with `Proof::new_data_integrity` +
//!      `VerifiableCredential::from_parts` (the HSM / out-of-process signer path).
//!
//! Run with:
//!   cargo run --example post_quantum
//!
//! > ML-DSA cryptosuite identifiers here (`mldsa{44,65,87}-jcs-2025`) are a provisional
//! > bilateral convention, not a finalized W3C standard — see the README.

use multibase::Base;
use verifiable_credential_toolkit::{
    bindings::{cbor::Cbor, protobuf::Protobuf, CredentialCodec},
    generate_keypair_bytes, generate_ml_dsa_keypair, Algorithm, Proof,
    UnsignedVerifiableCredential, VerifiableCredential,
};

fn sample_credential() -> UnsignedVerifiableCredential {
    serde_json::from_str(
        r#"{
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "DeviceCertificate"],
            "issuer": "https://example.com/issuers/pqc-authority",
            "credentialSubject": {
                "id": "urn:uuid:device-001",
                "name": "Temperature Sensor Alpha",
                "firmware": 42
            }
        }"#,
    )
    .expect("sample credential should parse")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Step 1: Every ML-DSA parameter set signs and verifies ───────────
    println!("=== Step 1: Sign + verify with each ML-DSA parameter set ===\n");
    for algorithm in [Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::MlDsa87] {
        let (private_key, public_key) = generate_keypair_bytes(algorithm);
        let signed = sample_credential().sign_with_algorithm(algorithm, &private_key)?;

        // `verify_auto` reads the algorithm from the proof's cryptosuite; the caller only
        // needs the public key bytes.
        signed.verify_auto(&public_key)?;
        // `verify_with_algorithm` asserts the algorithm explicitly.
        signed.verify_with_algorithm(algorithm, &public_key)?;

        println!(
            "  {:<9} private {:>4}B / public {:>4}B → cryptosuite {} ✓",
            format!("{algorithm:?}"),
            private_key.len(),
            public_key.len(),
            algorithm.cryptosuite(),
        );
    }

    // ── Step 2: Typed keys (algorithm carried by the key) ───────────────
    // `generate_ml_dsa_keypair` returns typed keys whose parameter set travels with the
    // bytes; `sign_ml_dsa` / `verify_ml_dsa` then can't be called with a mismatched
    // algorithm, and the verify rejects a proof whose cryptosuite names a different set.
    println!("\n=== Step 2: Typed ML-DSA keys ===\n");
    let typed = generate_ml_dsa_keypair(Algorithm::MlDsa65)?;
    let typed_signed = sample_credential().sign_ml_dsa(&typed.signing_key)?;
    typed_signed.verify_ml_dsa(&typed.verifying_key)?;
    println!("  sign_ml_dsa / verify_ml_dsa round-trip ✓");
    // A key for a different parameter set is refused (cryptosuite mismatch).
    let wrong = generate_ml_dsa_keypair(Algorithm::MlDsa44)?;
    println!(
        "  an ML-DSA-44 key is rejected on this ML-DSA-65 proof: {}",
        typed_signed.verify_ml_dsa(&wrong.verifying_key).is_err()
    );

    // ── Step 3: Hedged signing is non-deterministic ─────────────────────
    println!("\n=== Step 3: Hedged (randomized) signing ===\n");
    let (private_key, public_key) = generate_keypair_bytes(Algorithm::MlDsa65);
    let first = sample_credential().sign_with_algorithm(Algorithm::MlDsa65, &private_key)?;
    let second = sample_credential().sign_with_algorithm(Algorithm::MlDsa65, &private_key)?;
    println!(
        "  Two signatures over the same payload differ: {}",
        first.proof.proof_value() != second.proof.proof_value()
    );
    println!("  …and both still verify: {}", {
        first.verify_auto(&public_key).is_ok() && second.verify_auto(&public_key).is_ok()
    });

    // ── Step 4: One signature, three wire formats ───────────────────────
    // The signature is over the JCS canonical form, so a credential signed via the JSON
    // core verifies after being re-encoded as CBOR or Protobuf, with no re-signing.
    println!("\n=== Step 4: Cross-format interop (sign once, verify everywhere) ===\n");
    let signed = sample_credential().sign_with_algorithm(Algorithm::MlDsa65, &private_key)?;

    let cbor = Cbor::encode_signed(&signed)?;
    Cbor::verify_auto(&cbor, &public_key)?;
    println!("  signed as JSON, verified as CBOR     ✓");

    let protobuf = Protobuf::encode_signed(&signed)?;
    Protobuf::verify_auto(&protobuf, &public_key)?;
    println!("  signed as JSON, verified as Protobuf ✓");

    // Sign on CBOR bytes, transcode to Protobuf, verify there.
    let unsigned_cbor = Cbor::encode_unsigned(&sample_credential())?;
    let signed_cbor = Cbor::sign(&unsigned_cbor, Algorithm::MlDsa65, &private_key)?;
    let transcoded = Protobuf::encode_signed(&Cbor::decode_signed(&signed_cbor)?)?;
    Protobuf::verify_auto(&transcoded, &public_key)?;
    println!("  signed as CBOR, verified as Protobuf ✓");

    // ── Step 5: External / out-of-process signer (e.g. an HSM) ──────────
    // `signing_payload()` returns the exact JCS bytes to sign. Hand those to a
    // FIPS-validated module / HSM over FFI, get back a raw signature, then wrap it in a
    // DataIntegrityProof and attach it with `from_parts`.
    println!("\n=== Step 5: Inject an externally-computed signature ===\n");
    let unsigned = sample_credential();
    let payload = unsigned.signing_payload()?;
    println!(
        "  signing_payload() → {} canonical bytes to hand to the HSM",
        payload.len()
    );

    // Stand-in for the external signer: here we use the toolkit to produce a real ML-DSA
    // signature, then decode its multibase proofValue back to the raw bytes such a signer
    // would return. (A real HSM would compute these bytes itself, never touching this crate.)
    let raw_signature = {
        let (_, bytes) = multibase::decode(
            unsigned
                .clone()
                .sign_with_algorithm(Algorithm::MlDsa65, &private_key)?
                .proof
                .proof_value(),
        )?;
        bytes
    };

    // Wrap the raw signature and assemble the signed credential by hand.
    let proof = Proof::new_data_integrity(
        Algorithm::MlDsa65.cryptosuite(),
        multibase::encode(Base::Base58Btc, raw_signature),
    );
    let injected = VerifiableCredential::from_parts(unsigned, proof);
    injected.verify_auto(&public_key)?;
    println!("  externally-signed proof verifies ✓");

    println!("\n=== Done! ===");
    Ok(())
}
