//! Ed25519 (EdDSA) signature scheme.

use super::SignatureScheme;
use crate::crypto::random_seed;
use crate::VcError;
use ed25519_dalek::{
    Signature, Signer, SigningKey as DalekSigningKey, Verifier, VerifyingKey as DalekVerifyingKey,
};

/// Ed25519 (EdDSA) over 32-byte keys.
struct Ed25519Scheme;

impl SignatureScheme for Ed25519Scheme {
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, VcError> {
        let array: [u8; 32] = private_key
            .try_into()
            .map_err(|_| VcError::KeyDecode("Ed25519 signing key must be 32 bytes".to_string()))?;
        Ok(DalekSigningKey::from_bytes(&array)
            .sign(message)
            .to_bytes()
            .to_vec())
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), VcError> {
        let array: [u8; 32] = public_key.try_into().map_err(|_| {
            VcError::InvalidPublicKey("Ed25519 public key must be 32 bytes".to_string())
        })?;
        let sig = Signature::from_slice(signature)
            .map_err(|e| VcError::MalformedSignature(e.to_string()))?;
        DalekVerifyingKey::from_bytes(&array)
            .map_err(|e| VcError::InvalidPublicKey(e.to_string()))?
            .verify(message, &sig)
            .map_err(|_| VcError::SignatureVerificationFailed)
    }

    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>) {
        let signing_key = DalekSigningKey::from_bytes(&random_seed());
        (
            signing_key.to_bytes().to_vec(),
            signing_key.verifying_key().to_bytes().to_vec(),
        )
    }
}

/// The Ed25519 [SignatureScheme], boxed for runtime dispatch by [Algorithm::scheme](super::Algorithm::scheme).
pub(super) fn scheme() -> Box<dyn SignatureScheme> {
    Box::new(Ed25519Scheme)
}
