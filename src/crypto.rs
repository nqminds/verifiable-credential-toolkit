//! Signature algorithms and keys.
//!
//! The toolkit signs and verifies credentials with one of several algorithms — Ed25519
//! and the three ML-DSA (FIPS 204) parameter sets — behind a single model. A key is an
//! [Algorithm] tag plus raw bytes ([SigningKey] / [VerifyingKey]); ML-DSA is not
//! special-cased, it is just another [Algorithm]. The credential `sign` / `verify`
//! methods read the algorithm from the key, so the same call works for any algorithm.
//!
//! Internally each algorithm is a [SignatureScheme] implementation selected by
//! [Algorithm::scheme]; that trait is the seam where a FIPS-validated / HSM backend can be
//! dropped in as one more implementation without touching the public API.

use crate::VcError;
use ed25519_dalek::{
    Signature, Signer, SigningKey as DalekSigningKey, Verifier, VerifyingKey as DalekVerifyingKey,
};
use std::fmt;
use std::marker::PhantomData;

/// A signature algorithm the toolkit can sign and verify with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Algorithm {
    /// Ed25519 (EdDSA). 32-byte keys, `eddsa-jcs-2022` cryptosuite.
    Ed25519,
    /// ML-DSA-44 (FIPS 204, security category 2).
    MlDsa44,
    /// ML-DSA-65 (FIPS 204, security category 3).
    MlDsa65,
    /// ML-DSA-87 (FIPS 204, security category 5).
    MlDsa87,
}

impl Algorithm {
    /// The `cryptosuite` identifier written into a [Proof](crate::Proof) signed with this
    /// algorithm.
    ///
    /// Ed25519 uses the standardized `eddsa-jcs-2022`. The ML-DSA identifiers are
    /// **provisional and bilateral**: the W3C `vc-di-mldsa` cryptosuite is still a Working
    /// Draft with no finalized identifier, so these strings are a private convention that
    /// signing and verifying parties must agree on out of band (see the README). All use
    /// JCS (RFC 8785) canonicalization.
    pub fn cryptosuite(self) -> &'static str {
        match self {
            Algorithm::Ed25519 => "eddsa-jcs-2022",
            Algorithm::MlDsa44 => "mldsa44-jcs-2025",
            Algorithm::MlDsa65 => "mldsa65-jcs-2025",
            Algorithm::MlDsa87 => "mldsa87-jcs-2025",
        }
    }

    /// Map a proof `cryptosuite` identifier back to an [Algorithm], or `None` if the
    /// identifier is not one this library implements.
    pub fn from_cryptosuite(cryptosuite: &str) -> Option<Self> {
        match cryptosuite {
            "eddsa-jcs-2022" => Some(Algorithm::Ed25519),
            "mldsa44-jcs-2025" => Some(Algorithm::MlDsa44),
            "mldsa65-jcs-2025" => Some(Algorithm::MlDsa65),
            "mldsa87-jcs-2025" => Some(Algorithm::MlDsa87),
            _ => None,
        }
    }

    /// The raw key lengths `(private, public)` in bytes for this algorithm. For Ed25519
    /// both are 32; for ML-DSA these are the FIPS 204 sizes (and are pinned by the
    /// `keypair_byte_lengths_match_wire_contract` test). Used to length-check keys at
    /// construction.
    fn key_lengths(self) -> (usize, usize) {
        match self {
            Algorithm::Ed25519 => (32, 32),
            Algorithm::MlDsa44 => (2560, 1312),
            Algorithm::MlDsa65 => (4032, 1952),
            Algorithm::MlDsa87 => (4896, 2592),
        }
    }

    /// The single dispatch point from the runtime [Algorithm] tag to the compile-time
    /// [SignatureScheme] that implements it. Every sign / verify / keygen call routes
    /// through here, so this is the only place that enumerates the variants — adding an
    /// algorithm means adding one arm here plus one trait impl.
    fn scheme(self) -> Box<dyn SignatureScheme> {
        match self {
            Algorithm::Ed25519 => Box::new(Ed25519Scheme),
            Algorithm::MlDsa44 => Box::new(MlDsaScheme::<ml_dsa::MlDsa44>(PhantomData)),
            Algorithm::MlDsa65 => Box::new(MlDsaScheme::<ml_dsa::MlDsa65>(PhantomData)),
            Algorithm::MlDsa87 => Box::new(MlDsaScheme::<ml_dsa::MlDsa87>(PhantomData)),
        }
    }
}

/// Sign `message` with `algorithm` and a raw private key of the matching length, returning
/// the raw signature bytes. The credential-level wrapping (JCS payload, multibase, the
/// `DataIntegrityProof`) lives in the crate root.
pub(crate) fn sign_bytes(
    algorithm: Algorithm,
    private_key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, VcError> {
    algorithm.scheme().sign(private_key, message)
}

/// Verify a raw `signature` over `message` with `algorithm` and a raw public key.
pub(crate) fn verify_bytes(
    algorithm: Algorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VcError> {
    algorithm.scheme().verify(public_key, message, signature)
}

/// The per-algorithm signing operations, behind one interface. Implemented by a
/// zero-sized marker per scheme ([Ed25519Scheme], [MlDsaScheme]) and selected at runtime
/// by [Algorithm::scheme]. Keeping this private means the public API stays the [Algorithm]
/// enum and the key types; this trait only removes the duplicated `match` arms and
/// provides the seam where a FIPS-validated / HSM backend can be dropped in as one extra
/// impl.
trait SignatureScheme {
    /// Sign `message` with a raw private key of this scheme's expected length.
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, VcError>;
    /// Verify a raw `signature` over `message` with a raw public key.
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), VcError>;
    /// Generate a fresh key pair, returning `(private_key, public_key)` as raw bytes.
    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>);
}

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

/// Fill a fresh 32-byte seed from the operating-system CSPRNG, accessed directly through
/// `getrandom` — the same entropy source `rand::OsRng` wraps. Panics only if the OS RNG is
/// unavailable, which is unrecoverable and matches the previous `OsRng`-based behavior.
fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    getrandom_v04::fill(&mut seed).expect("operating-system RNG is unavailable");
    seed
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

/// Generate a fresh key pair for `algorithm`, returning `(private_key, public_key)` as raw
/// bytes suitable for [sign_with_algorithm](crate::UnsignedVerifiableCredential::sign_with_algorithm)
/// and [verify_with_algorithm](crate::VerifiableCredential::verify_with_algorithm). For
/// typed keys that carry their algorithm, use [generate_keypair].
pub fn generate_keypair_bytes(algorithm: Algorithm) -> (Vec<u8>, Vec<u8>) {
    algorithm.scheme().generate_keypair()
}

/// Whether a key is a private (signing) or public (verifying) key — selects which length a
/// key is checked against.
#[derive(Clone, Copy)]
enum KeyRole {
    Signing,
    Verifying,
}

/// Validate that `len` matches `algorithm`'s key length for the given `role`.
fn check_key_length(algorithm: Algorithm, len: usize, role: KeyRole) -> Result<(), VcError> {
    let (private_len, public_len) = algorithm.key_lengths();
    let (expected, label) = match role {
        KeyRole::Signing => (private_len, "signing"),
        KeyRole::Verifying => (public_len, "verifying"),
    };
    if len != expected {
        return Err(VcError::KeyDecode(format!(
            "{algorithm:?} {label} key must be {expected} bytes, got {len}"
        )));
    }
    Ok(())
}

/// A private (signing) key: an [Algorithm] tag plus its raw key bytes.
///
/// The algorithm travels with the bytes, so [sign](crate::UnsignedVerifiableCredential::sign)
/// reads it from the key and a caller never has to pass the algorithm separately. The byte
/// length is checked against the algorithm at construction. For raw-byte interop (an HSM,
/// the wasm ABI, a cross-language partner) use
/// [sign_with_algorithm](crate::UnsignedVerifiableCredential::sign_with_algorithm) with the
/// raw bytes instead.
#[derive(Clone)]
pub struct SigningKey {
    algorithm: Algorithm,
    bytes: Vec<u8>,
}

/// A public (verifying) key: an [Algorithm] tag plus its raw key bytes. See [SigningKey].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VerifyingKey {
    algorithm: Algorithm,
    bytes: Vec<u8>,
}

impl SigningKey {
    /// Wrap raw signing-key bytes for `algorithm`, checking the length matches (Ed25519:
    /// 32 bytes; ML-DSA: the FIPS 204 expanded signing key). Errors with
    /// [VcError::KeyDecode] on a length mismatch.
    pub fn new(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, VcError> {
        check_key_length(algorithm, bytes.len(), KeyRole::Signing)?;
        Ok(Self {
            algorithm,
            bytes: bytes.to_vec(),
        })
    }

    /// The algorithm this key signs with.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl VerifyingKey {
    /// Wrap raw verifying-key bytes for `algorithm`, checking the length matches (Ed25519:
    /// 32 bytes; ML-DSA: the FIPS 204 public key). Errors with [VcError::KeyDecode] on a
    /// length mismatch.
    pub fn new(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, VcError> {
        check_key_length(algorithm, bytes.len(), KeyRole::Verifying)?;
        Ok(Self {
            algorithm,
            bytes: bytes.to_vec(),
        })
    }

    /// The algorithm this key verifies.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// Redact the secret in Debug output so it can't leak into logs.
impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("algorithm", &self.algorithm)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// A key pair produced by [generate_keypair].
#[derive(Clone)]
pub struct KeyPair {
    /// The private key used to sign credentials.
    pub signing_key: SigningKey,
    /// The public key used to verify credentials.
    pub verifying_key: VerifyingKey,
}

/// Generate a fresh typed [KeyPair] for `algorithm`. The algorithm travels with each key,
/// so the resulting keys can be passed straight to
/// [sign](crate::UnsignedVerifiableCredential::sign) /
/// [verify](crate::VerifiableCredential::verify).
pub fn generate_keypair(algorithm: Algorithm) -> KeyPair {
    let (signing_key, verifying_key) = generate_keypair_bytes(algorithm);
    KeyPair {
        signing_key: SigningKey {
            algorithm,
            bytes: signing_key,
        },
        verifying_key: VerifyingKey {
            algorithm,
            bytes: verifying_key,
        },
    }
}
