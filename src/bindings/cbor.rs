use crate::bindings::CredentialCodec;
use crate::UnsignedVerifiableCredential;
use crate::VcError;
use crate::VerifiableCredential;
use c2pa_cbor::{from_slice, to_vec};

/// The CBOR serialization format.
///
/// Sign and verify through the [CredentialCodec] methods: `Cbor::sign(bytes, alg, sk)`,
/// `Cbor::verify_auto(bytes, pk)`, etc.
pub struct Cbor;

impl CredentialCodec for Cbor {
    fn decode_unsigned(bytes: &[u8]) -> Result<UnsignedVerifiableCredential, VcError> {
        from_slice(bytes).map_err(|e| VcError::Codec(Box::new(e)))
    }

    fn decode_signed(bytes: &[u8]) -> Result<VerifiableCredential, VcError> {
        from_slice(bytes).map_err(|e| VcError::Codec(Box::new(e)))
    }

    fn encode_unsigned(vc: &UnsignedVerifiableCredential) -> Result<Vec<u8>, VcError> {
        to_vec(vc).map_err(|e| VcError::Codec(Box::new(e)))
    }

    fn encode_signed(vc: &VerifiableCredential) -> Result<Vec<u8>, VcError> {
        to_vec(vc).map_err(|e| VcError::Codec(Box::new(e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_keypair_bytes, Algorithm};
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
        let (private_key, public_key) = generate_keypair_bytes(Algorithm::Ed25519);

        let cbor = Cbor::encode_unsigned(&sample_unsigned_vc()).expect("CBOR encode failed");
        let signed_bytes =
            Cbor::sign(&cbor, Algorithm::Ed25519, &private_key).expect("CBOR signing failed");

        Cbor::verify(&signed_bytes, Algorithm::Ed25519, &public_key)
            .expect("CBOR verification failed");
    }
}
