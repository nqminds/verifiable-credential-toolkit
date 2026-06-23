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

    /// The decoded `proofValue` was not a well-formed signature for the proof's
    /// cryptosuite (e.g. wrong length).
    #[error("malformed signature in proof: {0}")]
    MalformedSignature(String),

    /// The supplied public key bytes were not a valid Ed25519 verifying key.
    #[error("invalid public key")]
    InvalidPublicKey(#[source] ed25519_dalek::SignatureError),

    /// A public or private key could not be parsed (e.g. from PEM/SPKI), or its
    /// encoding did not match the expected algorithm.
    #[error("failed to parse key: {0}")]
    KeyParse(String),

    /// The key's algorithm (or a PEM/SPKI key OID) is not one this library supports.
    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(String),

    /// The signature did not verify against the credential and public key.
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// A serialization-format codec (e.g. CBOR or Protobuf) failed to decode or
    /// encode a credential. Carries the underlying format-specific error.
    #[error("codec error: {0}")]
    Codec(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The proof's `cryptosuite` is not one this library can verify. Carries the
    /// unsupported cryptosuite identifier (or a placeholder when none was present).
    #[error("unsupported proof cryptosuite: {0}")]
    UnsupportedCryptosuite(String),
}
