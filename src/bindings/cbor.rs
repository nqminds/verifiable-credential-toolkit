use crate::bindings::{
    sign_via, sign_with_algorithm_via, verify_auto_via, verify_via, verify_with_algorithm_via,
    CredentialCodec,
};
use crate::UnsignedVerifiableCredential;
use crate::VerifiableCredential;
use crate::{Algorithm, SigningKey, VcError, VerifyingKey};
use c2pa_cbor::{from_slice, to_vec};

/// The CBOR serialization format.
pub struct Cbor;

impl CredentialCodec for Cbor {
    fn decode_unsigned(bytes: &[u8]) -> Result<UnsignedVerifiableCredential, VcError> {
        decode_unsigned_vc_from_cbor(bytes).map_err(|e| VcError::Codec(Box::new(e)))
    }

    fn decode_signed(bytes: &[u8]) -> Result<VerifiableCredential, VcError> {
        decode_signed_vc_from_cbor(bytes).map_err(|e| VcError::Codec(Box::new(e)))
    }

    fn encode_signed(vc: &VerifiableCredential) -> Result<Vec<u8>, VcError> {
        encode_signed_vc_to_cbor(vc).map_err(|e| VcError::Codec(Box::new(e)))
    }
}

/// Decode cbor bytes into the existing unsigned VC Rust struct.
pub fn decode_unsigned_vc_from_cbor(
    bytes: &[u8],
) -> Result<UnsignedVerifiableCredential, c2pa_cbor::Error> {
    from_slice(bytes)
}

/// Decode cbor bytes into the existing signed VC Rust struct.
pub fn decode_signed_vc_from_cbor(bytes: &[u8]) -> Result<VerifiableCredential, c2pa_cbor::Error> {
    from_slice(bytes)
}

/// Encode an unsigned VC Rust struct into cbor bytes.
pub fn encode_unsigned_vc_to_cbor(
    vc: &UnsignedVerifiableCredential,
) -> Result<Vec<u8>, c2pa_cbor::Error> {
    to_vec(&vc)
}

/// Encode the existing signed VC Rust struct into cbor bytes.
pub fn encode_signed_vc_to_cbor(vc: &VerifiableCredential) -> Result<Vec<u8>, c2pa_cbor::Error> {
    to_vec(&vc)
}

/// Convenience wrapper: decode unsigned VC cbor, sign it, and re-encode as cbor.
pub fn sign_cbor_vc(unsigned_vc_cbor: &[u8], signing_key: &SigningKey) -> Result<Vec<u8>, VcError> {
    sign_via::<Cbor>(unsigned_vc_cbor, signing_key)
}

/// Convenience wrapper: decode signed VC cbor and verify its signature.
pub fn verify_cbor_vc(signed_vc_cbor: &[u8], verifying_key: &VerifyingKey) -> Result<(), VcError> {
    verify_via::<Cbor>(signed_vc_cbor, verifying_key)
}

/// Decode unsigned VC cbor, sign with the given [Algorithm] + raw private key, re-encode
/// as cbor. Supports every cryptosuite (Ed25519, ML-DSA-44/65/87).
pub fn sign_cbor_vc_with_algorithm(
    unsigned_vc_cbor: &[u8],
    algorithm: Algorithm,
    private_key: &[u8],
) -> Result<Vec<u8>, VcError> {
    sign_with_algorithm_via::<Cbor>(unsigned_vc_cbor, algorithm, private_key)
}

/// Decode signed VC cbor and verify with an explicit [Algorithm] + raw public key.
pub fn verify_cbor_vc_with_algorithm(
    signed_vc_cbor: &[u8],
    algorithm: Algorithm,
    public_key: &[u8],
) -> Result<(), VcError> {
    verify_with_algorithm_via::<Cbor>(signed_vc_cbor, algorithm, public_key)
}

/// Decode signed VC cbor and verify, reading the algorithm from the proof's
/// `cryptosuite`. The caller supplies only the raw public key bytes.
pub fn verify_cbor_vc_auto(signed_vc_cbor: &[u8], public_key: &[u8]) -> Result<(), VcError> {
    verify_auto_via::<Cbor>(signed_vc_cbor, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keypair;
    use serde_json::json;

    fn sample_unsigned_vc() -> UnsignedVerifiableCredential {
        serde_json::from_value(json!({
          "@context": ["https://www.w3.org/ns/credentials/v2"],
          "id": "urn:uuid:9a3e3c0e-2db0-412a-95c7-cf5520ba78df",
          "type": ["VerifiableCredential", "ExampleVerifiableCredential"],
          "issuer": "https://www.example.com/",
          "validFrom": "2024-08-22T13:53:32.295644150Z",
          "credentialSchema": {
            "id": "https://www.example.com/foo.json",
            "type": "JsonSchema"
          },
          "credentialSubject": {
            "name": "HenryTrustPhone",
            "id": "HenryTrustPhone-id"
          }
        }
        ))
        .expect("sample unsigned VC should deserialize")
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let keypair = generate_keypair();

        let unsigned_vc = sample_unsigned_vc();

        let cbor: Vec<u8> = to_vec(&unsigned_vc).expect("failed to serialize unsigned VC to CBOR");
        let signed_bytes = sign_cbor_vc(&cbor, &keypair.signing_key).expect("CBOR signing failed");

        verify_cbor_vc(&signed_bytes, &keypair.verifying_key).expect("cbor verification failed");
    }
}
