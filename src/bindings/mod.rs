//! Serialization-format bindings for verifiable credentials.
//!
//! Each wire format (CBOR, Protobuf, …) implements [CredentialCodec], which lets the
//! sign/verify pipelines be written once, generically over the format, rather than
//! duplicated per format.

use crate::{
    SigningKey, UnsignedVerifiableCredential, VcError, VerifiableCredential, VerifyingKey,
};

pub mod cbor;
pub mod protobuf;

/// A serialization format that can decode and encode verifiable credentials.
///
/// Implementors only describe how to move between bytes and the domain types; the
/// shared [sign_via] / [verify_via] pipelines provide the actual signing and
/// verification on top.
pub trait CredentialCodec {
    /// Decode an unsigned credential from this format's bytes.
    fn decode_unsigned(bytes: &[u8]) -> Result<UnsignedVerifiableCredential, VcError>;

    /// Decode a signed credential from this format's bytes.
    fn decode_signed(bytes: &[u8]) -> Result<VerifiableCredential, VcError>;

    /// Encode a signed credential into this format's bytes.
    fn encode_signed(vc: &VerifiableCredential) -> Result<Vec<u8>, VcError>;
}

/// Decode an unsigned credential in format `C`, sign it, and re-encode the signed
/// credential in the same format.
pub fn sign_via<C: CredentialCodec>(
    unsigned_bytes: &[u8],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, VcError> {
    let signed = C::decode_unsigned(unsigned_bytes)?.sign(signing_key)?;
    C::encode_signed(&signed)
}

/// Decode a signed credential in format `C` and verify its signature.
pub fn verify_via<C: CredentialCodec>(
    signed_bytes: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<(), VcError> {
    C::decode_signed(signed_bytes)?.verify(verifying_key)
}
