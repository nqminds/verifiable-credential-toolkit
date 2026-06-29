//! Typed errors for the verifiable credential toolkit.
//!
//! All fallible operations on [`UnsignedVerifiableCredential`](crate::UnsignedVerifiableCredential)
//! and [`VerifiableCredential`](crate::VerifiableCredential) return [`VcError`], so
//! callers can match on the specific failure rather than parsing an opaque string.

use thiserror::Error;

/// Errors that can occur while validating, signing, or verifying a credential.
#[derive(Debug, Error)]
pub enum VcError {
    /// The supplied private key was not 32 bytes.
    #[error("invalid private key length: expected 32 bytes")]
    InvalidPrivateKeyLength,

    /// The supplied public key was not 32 bytes.
    #[error("invalid public key length: expected 32 bytes")]
    InvalidPublicKeyLength,

    /// The `credentialSubject` did not satisfy the supplied JSON Schema.
    #[error("credential subject does not match schema")]
    SchemaMismatch,

    /// Failed to fetch a schema referenced by
    /// [`SchemaSource::Url`](crate::SchemaSource::Url).
    #[cfg(not(target_arch = "wasm32"))]
    #[error("failed to fetch schema from URL: {0}")]
    SchemaFetch(#[from] reqwest::Error),

    /// JSON (de)serialization failed, e.g. while serializing the credential to
    /// produce the signing payload or parsing a fetched schema.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The credential's `validFrom` is in the future.
    #[error("the credential is not yet valid (validFrom check failed)")]
    NotYetValid,

    /// The credential's `validUntil` is in the past.
    #[error("the credential has expired (validUntil check failed)")]
    Expired,

    /// The `proofValue` could not be decoded from its multibase representation.
    #[error("failed to decode proofValue: {0}")]
    ProofDecode(String),

    /// The decoded `proofValue` was not a well-formed signature for the proof's algorithm
    /// (e.g. wrong length).
    #[error("malformed signature in proof: {0}")]
    MalformedSignature(String),

    /// The supplied public key bytes were not a valid key for the expected algorithm.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// A key could not be decoded, or its length did not match the algorithm.
    #[error("failed to decode key: {0}")]
    KeyDecode(String),

    /// The proof's `cryptosuite` (or the requested algorithm) is not one this library
    /// can sign or verify.
    #[error("unsupported cryptosuite: {0}")]
    UnsupportedCryptosuite(String),

    /// The proof carries no `cryptosuite`, so the verification algorithm cannot be
    /// determined. `DataIntegrityProof` requires one; a proof without it is rejected
    /// rather than being assumed to be Ed25519.
    #[error("proof is missing a cryptosuite")]
    MissingCryptosuite,

    /// The signature did not verify against the credential and public key.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// A serialization-format codec (e.g. CBOR or Protobuf) failed to decode or
    /// encode a credential. Carries the underlying format-specific error.
    #[error("codec error: {0}")]
    Codec(#[source] Box<dyn std::error::Error + Send + Sync>),
}
