use crate::UnsignedVerifiableCredential;
use crate::VerifiableCredential;
use c2pa_cbor::{from_slice, to_vec};

/// Decode cbor bytes into the existing unsigned VC Rust struct.
pub fn decode_unsigned_vc_from_cbor(
    bytes: &[u8],
) -> Result<UnsignedVerifiableCredential, c2pa_cbor::Error> {
    let decoded: Result<UnsignedVerifiableCredential, c2pa_cbor::Error> = from_slice(bytes);
    decoded
}

/// Decode cbor bytes into the existing signed VC Rust struct.
pub fn decode_signed_vc_from_cbor(bytes: &[u8]) -> Result<VerifiableCredential, c2pa_cbor::Error> {
    let decoded: Result<VerifiableCredential, c2pa_cbor::Error> = from_slice(bytes);
    decoded
}

/// Encode the existing signed VC Rust struct into cbor bytes.
pub fn encode_signed_vc_to_cbor(vc: &VerifiableCredential) -> Result<Vec<u8>, c2pa_cbor::Error> {
    let encoded: Result<Vec<u8>, c2pa_cbor::Error> = to_vec(&vc);
    encoded
}

pub fn sign_cbor_vc(
    unsigned_vc_cbor: &[u8],
    private_key: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let decoded = decode_unsigned_vc_from_cbor(unsigned_vc_cbor)?;
    let signed = decoded.sign(private_key)?;

    Ok(encode_signed_vc_to_cbor(&signed)?)
}

/// Convenience wrapper: decode signed VC cbor and verify with existing JSON-path logic.
pub fn verify_cbor_vc(
    signed_vc_cbor: &[u8],
    public_key: &[u8],
) -> Result<(), Box<dyn std::error::Error + 'static>> {
    let decoded = decode_signed_vc_from_cbor(signed_vc_cbor)?;
    decoded.verify(public_key)
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
        let (private_key, public_key) = generate_keypair();

        let unsigned_vc = sample_unsigned_vc();

        let cbor: Vec<u8> = to_vec(&unsigned_vc).expect("failed to serialize unsigned VC to CBOR");
        let signed_bytes = sign_cbor_vc(&cbor, &private_key).expect("CBOR signing failed");

        verify_cbor_vc(&signed_bytes, &public_key).expect("cbor verification failed");
    }
}
