use crate::proto_schemas::vc::UnsignedVerifiableCredential as ProtobufUnsignedVerifiableCredential;
use crate::proto_schemas::vc::VerifiableCredential as ProtobufVerifiableCredential;
use crate::UnsignedVerifiableCredential;
use crate::VerifiableCredential;
use protobuf::Message;
use protobuf_json_mapping::{
    parse_from_str as json_to_protobuf, print_to_string as protobuf_to_json,
};

pub type ProtoResult<T> = Result<T, String>;

fn protobuf_signed_to_domain(
    protobuf: ProtobufVerifiableCredential,
) -> ProtoResult<VerifiableCredential> {
    let json = protobuf_to_json(&protobuf)
        .map_err(|e| format!("protobuf->json conversion failed: {e}"))?;
    serde_json::from_str::<VerifiableCredential>(&json)
        .map_err(|e| format!("json->VerifiableCredential conversion failed: {e}"))
}

fn protobuf_unsigned_to_domain(
    protobuf: ProtobufUnsignedVerifiableCredential,
) -> ProtoResult<UnsignedVerifiableCredential> {
    let json = protobuf_to_json(&protobuf)
        .map_err(|e| format!("protobuf->json conversion failed: {e}"))?;
    serde_json::from_str::<UnsignedVerifiableCredential>(&json)
        .map_err(|e| format!("json->UnsignedVerifiableCredential conversion failed: {e}"))
}

/// Decode protobuf bytes into the protobuf-generated unsigned VC struct.
pub fn decode_unsigned_vc_from_protobuf(
    bytes: &[u8],
) -> ProtoResult<ProtobufUnsignedVerifiableCredential> {
    ProtobufUnsignedVerifiableCredential::parse_from_bytes(bytes)
        .map_err(|e| format!("invalid protobuf: {e}"))
}

/// Decode protobuf bytes into the protobuf-generated signed VC struct.
pub fn decode_signed_vc_from_protobuf(bytes: &[u8]) -> ProtoResult<ProtobufVerifiableCredential> {
    ProtobufVerifiableCredential::parse_from_bytes(bytes)
        .map_err(|e| format!("invalid protobuf: {e}"))
}

/// Encode the existing signed VC Rust struct into protobuf bytes.
pub fn encode_signed_vc_to_protobuf(vc: &VerifiableCredential) -> ProtoResult<Vec<u8>> {
    let json = serde_json::to_string(vc)
        .map_err(|e| format!("VerifiableCredential->json conversion failed: {e}"))?;

    let protobuf: ProtobufVerifiableCredential =
        json_to_protobuf(&json).map_err(|e| format!("json->protobuf conversion failed: {e}"))?;

    protobuf
        .write_to_bytes()
        .map_err(|e| format!("protobuf serialization failed: {e}"))
}

/// Convenience wrapper: decode unsigned VC protobuf, sign with existing JSON-path logic, re-encode as protobuf.
pub fn sign_protobuf_vc(unsigned_vc_protobuf: &[u8], private_key: &[u8]) -> ProtoResult<Vec<u8>> {
    let signed_vc = {
        let unsigned_vc = decode_unsigned_vc_from_protobuf(unsigned_vc_protobuf)?;
        let unsigned_vc2 = protobuf_unsigned_to_domain(unsigned_vc);
        unsigned_vc2?.sign(private_key)
    };
    match signed_vc {
        Ok(vc) => encode_signed_vc_to_protobuf(&vc),
        Err(e) => Err(format!("signing failed: {e}")),
    }
}

/// Convenience wrapper: decode signed VC protobuf and verify with existing JSON-path logic.
pub fn verify_protobuf_vc(signed_vc_protobuf: &[u8], public_key: &[u8]) -> ProtoResult<()> {
    let signed_vc = decode_signed_vc_from_protobuf(signed_vc_protobuf)?;
    let signed_vc2 = protobuf_signed_to_domain(signed_vc)?;
    signed_vc2
        .verify(public_key)
        .map_err(|e| format!("verification failed: {e}"))
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
        let (private_key, public_key) = generate_keypair();

        let unsigned_vc = sample_unsigned_vc();
        let json = serde_json::to_string(&unsigned_vc).expect("failed to serialize unsigned VC");

        let protobuf: ProtobufUnsigned =
            protobuf_json_mapping::parse_from_str(&json).expect("json->protobuf conversion failed");
        let unsigned_bytes = protobuf
            .write_to_bytes()
            .expect("protobuf serialization failed");

        let signed_bytes =
            sign_protobuf_vc(&unsigned_bytes, &private_key).expect("protobuf signing failed");

        verify_protobuf_vc(&signed_bytes, &public_key).expect("protobuf verification failed");
    }
}
