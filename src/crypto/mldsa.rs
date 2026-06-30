//! ML-DSA (FIPS 204) signature scheme, for the three parameter sets.
//!
//! This is the single file that depends on the `ml-dsa` backend crate. To swap in a
//! different ML-DSA implementation (e.g. a FIPS-validated module or an HSM over FFI), this
//! is the only place that changes — the rest of the toolkit talks to [SignatureScheme].

use super::SignatureScheme;
use crate::crypto::random_seed;
use crate::VcError;
use std::marker::PhantomData;

/// ML-DSA (FIPS 204) for a given parameter set `P` (`MlDsa44` / `MlDsa65` / `MlDsa87`).
/// Thin adapter over the `mldsa_*` helpers, which own the hedged-signing and panic-guard
/// details.
struct MlDsaScheme<P>(PhantomData<P>);

impl<P: ml_dsa::MlDsaParams> SignatureScheme for MlDsaScheme<P> {
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, VcError> {
        mldsa_sign::<P>(private_key, message)
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), VcError> {
        mldsa_verify::<P>(public_key, message, signature)
    }

    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>) {
        mldsa_generate::<P>()
    }
}

/// Sign `message` with a raw FIPS 204 expanded ML-DSA signing key, returning the raw
/// signature bytes. Uses the **hedged** (randomized) variant with an empty context, as
/// recommended by FIPS 204 §3.4 — fresh randomness mitigates fault attacks and bad-RNG
/// edge cases. Signatures are therefore non-deterministic (still verifiable by anyone).
///
/// `from_expanded` does not validate the key and can panic on a malformed (but
/// correctly-sized) key. The private key is caller-supplied, so the whole sign is run
/// inside `catch_unwind` and a panic is reported as a [VcError] rather than aborting.
#[allow(deprecated)] // from_expanded: importing an external expanded key is the intent here
fn mldsa_sign<P: ml_dsa::MlDsaParams>(sk_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, VcError> {
    let encoded = ml_dsa::ExpandedSigningKeyBytes::<P>::try_from(sk_bytes)
        .map_err(|_| VcError::KeyDecode("ML-DSA signing key has the wrong length".to_string()))?;

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let signing_key = ml_dsa::ExpandedSigningKey::<P>::from_expanded(&encoded);
        signing_key.sign_randomized(message, b"", &mut getrandom_v04::SysRng)
    }))
    .map_err(|_| VcError::KeyDecode("ML-DSA signing key is malformed".to_string()))?;

    let signature = result.map_err(|_| VcError::KeyDecode("ML-DSA signing failed".to_string()))?;
    Ok(signature.encode().to_vec())
}

/// Verify a raw ML-DSA signature over `message` with a raw FIPS 204 public key.
fn mldsa_verify<P: ml_dsa::MlDsaParams>(
    pk_bytes: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VcError> {
    let encoded_pk = ml_dsa::EncodedVerifyingKey::<P>::try_from(pk_bytes).map_err(|_| {
        VcError::InvalidPublicKey("ML-DSA public key has the wrong length".to_string())
    })?;
    let verifying_key = ml_dsa::VerifyingKey::<P>::decode(&encoded_pk);

    let encoded_sig = ml_dsa::EncodedSignature::<P>::try_from(signature).map_err(|_| {
        VcError::MalformedSignature("ML-DSA signature has the wrong length".to_string())
    })?;
    let signature = ml_dsa::Signature::<P>::decode(&encoded_sig).ok_or_else(|| {
        VcError::MalformedSignature("ML-DSA signature failed to decode".to_string())
    })?;

    if verifying_key.verify_with_context(message, b"", &signature) {
        Ok(())
    } else {
        Err(VcError::SignatureVerificationFailed)
    }
}

/// Generate an ML-DSA key pair from a fresh random seed, returning
/// `(expanded_signing_key_bytes, verifying_key_bytes)` in their FIPS 204 encodings.
#[allow(deprecated)] // to_expanded: we intentionally export the expanded key form
fn mldsa_generate<P: ml_dsa::MlDsaParams>() -> (Vec<u8>, Vec<u8>) {
    let seed = random_seed();
    let seed = ml_dsa::B32::try_from(&seed[..]).expect("seed is 32 bytes");
    let signing_key = ml_dsa::ExpandedSigningKey::<P>::from_seed(&seed);
    (
        signing_key.to_expanded().to_vec(),
        signing_key.verifying_key().encode().to_vec(),
    )
}

/// The ML-DSA [SignatureScheme] for each parameter set, boxed for runtime dispatch by
/// [Algorithm::scheme](super::Algorithm::scheme).
pub(super) fn scheme_44() -> Box<dyn SignatureScheme> {
    Box::new(MlDsaScheme::<ml_dsa::MlDsa44>(PhantomData))
}

pub(super) fn scheme_65() -> Box<dyn SignatureScheme> {
    Box::new(MlDsaScheme::<ml_dsa::MlDsa65>(PhantomData))
}

pub(super) fn scheme_87() -> Box<dyn SignatureScheme> {
    Box::new(MlDsaScheme::<ml_dsa::MlDsa87>(PhantomData))
}
