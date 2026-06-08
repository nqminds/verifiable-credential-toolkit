use crate::bindings::{sign_via, verify_via, CredentialCodec};
use crate::proto_schemas::vc::UnsignedVerifiableCredential as ProtobufUnsignedVerifiableCredential;
use crate::proto_schemas::vc::VerifiableCredential as ProtobufVerifiableCredential;
use crate::UnsignedVerifiableCredential;
use crate::VerifiableCredential;
use crate::{SigningKey, VcError, VerifyingKey};
use protobuf::Message;
use protobuf_json_mapping::{
    parse_from_str as json_to_protobuf, print_to_string as protobuf_to_json,
};

pub type ProtoResult<T> = Result<T, Box<dyn std::error::Error>>;

/// The Protobuf serialization format.
///
/// Protobuf has no native dynamic JSON object, so credentials round-trip through the
/// protobuf<->JSON canonical mapping rather than via serde directly.
pub struct Protobuf;

/// Wrap a format-specific error in [VcError::Codec].
fn codec_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> VcError {
    VcError::Codec(Box::new(e))
}

impl CredentialCodec for Protobuf {
    fn decode_unsigned(bytes: &[u8]) -> Result<UnsignedVerifiableCredential, VcError> {
        let protobuf =
            ProtobufUnsignedVerifiableCredential::parse_from_bytes(bytes).map_err(codec_err)?;
        let json = protobuf_to_json(&protobuf).map_err(codec_err)?;
        Ok(serde_json::from_str(&json)?)
    }

    fn decode_signed(bytes: &[u8]) -> Result<VerifiableCredential, VcError> {
        let protobuf = ProtobufVerifiableCredential::parse_from_bytes(bytes).map_err(codec_err)?;
        let json = protobuf_to_json(&protobuf).map_err(codec_err)?;
        Ok(serde_json::from_str(&json)?)
    }

    fn encode_signed(vc: &VerifiableCredential) -> Result<Vec<u8>, VcError> {
        let json = serde_json::to_string(vc)?;
        let protobuf: ProtobufVerifiableCredential = json_to_protobuf(&json).map_err(codec_err)?;
        protobuf.write_to_bytes().map_err(codec_err)
    }
}

/// Decode protobuf bytes into the protobuf-generated unsigned VC struct.
pub fn decode_unsigned_vc_from_protobuf(
    bytes: &[u8],
) -> ProtoResult<ProtobufUnsignedVerifiableCredential> {
    Ok(ProtobufUnsignedVerifiableCredential::parse_from_bytes(
        bytes,
    )?)
}

/// Decode protobuf bytes into the protobuf-generated signed VC struct.
pub fn decode_signed_vc_from_protobuf(bytes: &[u8]) -> ProtoResult<ProtobufVerifiableCredential> {
    Ok(ProtobufVerifiableCredential::parse_from_bytes(bytes)?)
}

/// Encode the existing signed VC Rust struct into protobuf bytes.
pub fn encode_signed_vc_to_protobuf(vc: &VerifiableCredential) -> ProtoResult<Vec<u8>> {
    let json = serde_json::to_string(vc)?;
    let protobuf: ProtobufVerifiableCredential = json_to_protobuf(&json)?;
    Ok(protobuf.write_to_bytes()?)
}

/// Convenience wrapper: decode unsigned VC protobuf, sign it, and re-encode as protobuf.
pub fn sign_protobuf_vc(
    unsigned_vc_protobuf: &[u8],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, VcError> {
    sign_via::<Protobuf>(unsigned_vc_protobuf, signing_key)
}

/// Convenience wrapper: decode signed VC protobuf and verify its signature.
pub fn verify_protobuf_vc(
    signed_vc_protobuf: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<(), VcError> {
    verify_via::<Protobuf>(signed_vc_protobuf, verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        generate_keypair, proto_schemas::vc::UnsignedVerifiableCredential as ProtobufUnsigned,
    };
    use protobuf::Message;
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
        let json = serde_json::to_string(&unsigned_vc).expect("failed to serialize unsigned VC");

        let protobuf: ProtobufUnsigned =
            protobuf_json_mapping::parse_from_str(&json).expect("json->protobuf conversion failed");
        let unsigned_bytes = protobuf
            .write_to_bytes()
            .expect("protobuf serialization failed");

        let signed_bytes = sign_protobuf_vc(&unsigned_bytes, &keypair.signing_key)
            .expect("protobuf signing failed");

        verify_protobuf_vc(&signed_bytes, &keypair.verifying_key)
            .expect("protobuf verification failed");
    }
}
