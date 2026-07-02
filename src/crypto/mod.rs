//! Signature algorithms and keys.
//!
//! The toolkit signs and verifies credentials with one of several algorithms — Ed25519
//! and the three ML-DSA (FIPS 204) parameter sets — behind a single model. A key is an
//! [Algorithm] tag plus raw bytes ([SigningKey] / [VerifyingKey]); ML-DSA is not
//! special-cased, it is just another [Algorithm]. The credential `sign` / `verify`
//! methods read the algorithm from the key, so the same call works for any algorithm.
//!
//! Each algorithm is a [SignatureScheme] implementation living in its own submodule
//! ([ed25519], [mldsa]), selected at runtime by [Algorithm::scheme]. That trait is the seam
//! where a FIPS-validated / HSM backend can be dropped in as one more implementation
//! without touching the public API — and the per-algorithm split keeps each backend's
//! dependencies and details confined to one file.

mod ed25519;
mod mldsa;

use crate::VcError;
use std::fmt;

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

    /// The single dispatch point from the runtime [Algorithm] tag to the [SignatureScheme]
    /// that implements it. Every sign / verify / keygen call routes through here, so this
    /// is the only place that enumerates the variants — adding an algorithm means adding one
    /// arm here plus one submodule.
    fn scheme(self) -> Box<dyn SignatureScheme> {
        match self {
            Algorithm::Ed25519 => ed25519::scheme(),
            Algorithm::MlDsa44 => mldsa::scheme_44(),
            Algorithm::MlDsa65 => mldsa::scheme_65(),
            Algorithm::MlDsa87 => mldsa::scheme_87(),
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

/// The per-algorithm signing operations, behind one interface. Implemented once per
/// algorithm in the [ed25519] / [mldsa] submodules and selected at runtime by
/// [Algorithm::scheme]. Keeping this private means the public API stays the [Algorithm]
/// enum and the key types; this trait only removes the duplicated `match` arms and provides
/// the seam where a FIPS-validated / HSM backend can be dropped in as one extra impl.
trait SignatureScheme {
    /// Sign `message` with a raw private key of this scheme's expected length.
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, VcError>;
    /// Verify a raw `signature` over `message` with a raw public key.
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), VcError>;
    /// Generate a fresh key pair, returning `(private_key, public_key)` as raw bytes.
    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>);
}

/// Fill a fresh 32-byte seed from the operating-system CSPRNG, accessed directly through
/// `getrandom`. Shared by the per-algorithm key generators. Panics only if the OS RNG is
/// unavailable, which is unrecoverable.
fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    getrandom_v04::fill(&mut seed).expect("operating-system RNG is unavailable");
    seed
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
