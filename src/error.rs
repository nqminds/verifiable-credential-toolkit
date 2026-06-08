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

    /// The `proofValue` was not valid base64.
    #[error("failed to decode proofValue from base64: {0}")]
    ProofDecode(#[from] base64::DecodeError),

    /// The decoded `proofValue` was not a well-formed Ed25519 signature.
    #[error("malformed signature in proof")]
    MalformedSignature(#[source] ed25519_dalek::SignatureError),

    /// The supplied public key bytes were not a valid Ed25519 verifying key.
    #[error("invalid public key")]
    InvalidPublicKey(#[source] ed25519_dalek::SignatureError),

    /// The signature did not verify against the credential and public key.
    #[error("signature verification failed")]
    SignatureVerificationFailed(#[source] ed25519_dalek::SignatureError),
}
