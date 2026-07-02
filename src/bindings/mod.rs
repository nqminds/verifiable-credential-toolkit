//! Serialization-format bindings for verifiable credentials.
//!
//! Each wire format (CBOR, Protobuf, …) implements [CredentialCodec] by supplying only
//! the four bytes↔domain conversions. The sign / verify / verify_auto pipeline is provided
//! once as default methods on the trait, so a format gets the full signing API for free and
//! the public surface stays "one codec type per format" rather than a bank of free
//! functions per format.

use crate::{Algorithm, UnsignedVerifiableCredential, VcError, VerifiableCredential};

pub mod cbor;
pub mod protobuf;

/// A serialization format that can decode and encode verifiable credentials.
///
/// Implementors describe only how to move between bytes and the domain types; the default
/// [sign](CredentialCodec::sign) / [verify](CredentialCodec::verify) /
/// [verify_auto](CredentialCodec::verify_auto) methods build the signing pipeline on top.
/// Because every signature is taken over the format-independent JCS canonical form, a
/// credential signed in one format with any supported cryptosuite verifies in any other.
///
/// ```no_run
/// # use verifiable_credential_toolkit::{Algorithm, bindings::{CredentialCodec, cbor::Cbor}};
/// # fn demo(unsigned_cbor: &[u8], sk: &[u8], pk: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
/// let signed = Cbor::sign(unsigned_cbor, Algorithm::MlDsa65, sk)?;
/// Cbor::verify_auto(&signed, pk)?;
/// # Ok(())
/// # }
/// ```
pub trait CredentialCodec {
    /// Decode an unsigned credential from this format's bytes.
    fn decode_unsigned(bytes: &[u8]) -> Result<UnsignedVerifiableCredential, VcError>;

    /// Decode a signed credential from this format's bytes.
    fn decode_signed(bytes: &[u8]) -> Result<VerifiableCredential, VcError>;

    /// Encode an unsigned credential into this format's bytes.
    fn encode_unsigned(vc: &UnsignedVerifiableCredential) -> Result<Vec<u8>, VcError>;

    /// Encode a signed credential into this format's bytes.
    fn encode_signed(vc: &VerifiableCredential) -> Result<Vec<u8>, VcError>;

    /// Decode an unsigned credential, sign it with the given [Algorithm] and raw private
    /// key, and re-encode the signed credential in the same format. Works for every
    /// supported cryptosuite (Ed25519, ML-DSA-44/65/87).
    fn sign(
        unsigned_bytes: &[u8],
        algorithm: Algorithm,
        private_key: &[u8],
    ) -> Result<Vec<u8>, VcError> {
        let signed =
            Self::decode_unsigned(unsigned_bytes)?.sign_with_algorithm(algorithm, private_key)?;
        Self::encode_signed(&signed)
    }

    /// Decode a signed credential and verify it with an explicit [Algorithm] and raw public
    /// key. Does not require the proof's `cryptosuite` to match (the caller asserts the
    /// algorithm).
    fn verify(signed_bytes: &[u8], algorithm: Algorithm, public_key: &[u8]) -> Result<(), VcError> {
        Self::decode_signed(signed_bytes)?.verify_with_algorithm(algorithm, public_key)
    }

    /// Decode a signed credential and verify it, reading the algorithm from the proof's
    /// `cryptosuite`. The caller supplies only the raw public key bytes. Returns
    /// [VcError::UnsupportedCryptosuite] if the proof names a suite this library can't verify.
    fn verify_auto(signed_bytes: &[u8], public_key: &[u8]) -> Result<(), VcError> {
        Self::decode_signed(signed_bytes)?.verify_auto(public_key)
    }
}
