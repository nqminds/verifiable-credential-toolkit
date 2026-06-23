use chrono::{DateTime, Utc};
use ed25519_dalek::{
    Signature, Signer, SigningKey as DalekSigningKey, Verifier, VerifyingKey as DalekVerifyingKey,
};
use multibase::Base;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::formats::PreferOne;
use serde_with::{serde_as, OneOrMany};
use std::collections::HashMap;
use std::fmt;
use url::Url;

pub mod bindings;
pub mod error;
pub mod proto_schemas;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use error::VcError;

/// A Verifiable Credential as defined by the W3C Verifiable Credentials Data Model v2.0 - <https://www.w3.org/TR/vc-data-model-2.0> WITHOUT the proof
#[serde_as]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct UnsignedVerifiableCredential {
    /// <https://www.w3.org/TR/vc-data-model-2.0/#contexts>
    #[serde(rename = "@context")]
    pub context: Vec<Url>,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#identifiers>
    pub id: Option<Url>,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#types>
    #[serde(rename = "type")]
    #[serde_as(as = "OneOrMany<_, PreferOne>")]
    pub credential_type: Vec<String>,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#names-and-descriptions>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<LanguageValue>,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#names-and-descriptions>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<LanguageValue>,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#issuer>
    pub issuer: Issuer,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#credential-subject>
    #[serde(rename = "credentialSubject")]
    pub credential_subject: Value,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#validity-period>
    #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#validity-period>
    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#status>
    #[serde(rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<Status>,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#data-schemas>
    #[serde_as(as = "Option<OneOrMany<_, PreferOne>>")]
    #[serde(rename = "credentialSchema", skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<Vec<CredentialSchema>>,
}

/// A fluent builder for [UnsignedVerifiableCredential].
///
/// Mirrors the consuming-`self` builder on [Proof]: start from
/// [UnsignedVerifiableCredential::builder] with the required fields, chain the
/// optional setters, then call [build](UnsignedVerifiableCredentialBuilder::build).
///
/// ```
/// # use verifiable_credential_toolkit::{UnsignedVerifiableCredential, Issuer};
/// # use url::Url;
/// # use serde_json::json;
/// let vc = UnsignedVerifiableCredential::builder(
///     vec![Url::parse("https://www.w3.org/ns/credentials/v2").unwrap()],
///     vec!["VerifiableCredential".to_string()],
///     Issuer::Url(Url::parse("https://example.com/issuer").unwrap()),
///     json!({ "id": "urn:uuid:device-1", "name": "Sensor A" }),
/// )
/// .id(Url::parse("urn:uuid:9a3e3c0e-2db0-412a-95c7-cf5520ba78df").unwrap())
/// .build();
/// ```
#[derive(Debug, Clone)]
pub struct UnsignedVerifiableCredentialBuilder {
    inner: UnsignedVerifiableCredential,
}

impl UnsignedVerifiableCredentialBuilder {
    /// Set the credential `id`.
    pub fn id(mut self, id: Url) -> Self {
        self.inner.id = Some(id);
        self
    }

    /// Set the credential `name`.
    pub fn name(mut self, name: LanguageValue) -> Self {
        self.inner.name = Some(name);
        self
    }

    /// Set the credential `description`.
    pub fn description(mut self, description: LanguageValue) -> Self {
        self.inner.description = Some(description);
        self
    }

    /// Set the `validFrom` timestamp.
    pub fn valid_from(mut self, valid_from: DateTime<Utc>) -> Self {
        self.inner.valid_from = Some(valid_from);
        self
    }

    /// Set the `validUntil` timestamp.
    pub fn valid_until(mut self, valid_until: DateTime<Utc>) -> Self {
        self.inner.valid_until = Some(valid_until);
        self
    }

    /// Set the `credentialStatus`.
    pub fn credential_status(mut self, credential_status: Status) -> Self {
        self.inner.credential_status = Some(credential_status);
        self
    }

    /// Set the `credentialSchema` list.
    pub fn credential_schema(mut self, credential_schema: Vec<CredentialSchema>) -> Self {
        self.inner.credential_schema = Some(credential_schema);
        self
    }

    /// Finish building and return the [UnsignedVerifiableCredential].
    pub fn build(self) -> UnsignedVerifiableCredential {
        self.inner
    }
}

/// A Verifiable Credential as defined by the W3C Verifiable Credentials Data Model v2.0 - <https://www.w3.org/TR/vc-data-model-2.0>, this adds the proof to the UnsignedVerifiableCredential struct
#[serde_as]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct VerifiableCredential {
    #[serde(flatten)]
    pub unsigned: UnsignedVerifiableCredential,
    pub proof: Proof,
}

/// A Verifiable Presentation as defined by the W3C Verifiable Credentials Data Model v2.0 - <https://www.w3.org/TR/vc-data-model-2.0/#verifiable-presentations>
#[serde_as]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct VerifiablePresentation {
    #[serde(rename = "@context")]
    pub context: Vec<Url>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Url>,
    #[serde(rename = "type")]
    #[serde_as(as = "OneOrMany<_, PreferOne>")]
    pub presentation_type: Vec<String>,
    #[serde(
        rename = "verifiableCredential",
        skip_serializing_if = "Option::is_none"
    )]
    #[serde_as(as = "Option<OneOrMany<_, PreferOne>>")]
    pub verifiable_credential: Option<Vec<VerifiableCredential>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<Holder>,
}

/// <https://www.w3.org/TR/vc-data-model-2.0/#holder>
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub enum Holder {
    Url(Url),
    Object(HolderObject),
}

/// <https://www.w3.org/TR/vc-data-model-2.0/#holder>
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct HolderObject {
    pub id: Url,
    #[serde(flatten)]
    pub additional_properties: Option<HashMap<String, Value>>,
}

/// <https://www.w3.org/TR/vc-data-model-2.0/#issuer>
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub enum Issuer {
    Url(Url),
    Object(IssuerObject),
}

/// <https://www.w3.org/TR/vc-data-model-2.0/#issuer>
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct IssuerObject {
    pub id: Url,
    #[serde(flatten)]
    pub additional_properties: Option<HashMap<String, Value>>,
}

/// <https://www.w3.org/TR/vc-data-model-2.0/#names-and-descriptions>
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub enum LanguageValue {
    PlainString(String),
    LanguageObject(LanguageObject),
}

/// <https://www.w3.org/TR/vc-data-model-2.0/#language-and-base-direction>
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct LanguageObject {
    #[serde(rename = "@value")]
    pub value: String,
    #[serde(rename = "@language", skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(rename = "@direction", skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
}
/// <https://www.w3.org/TR/vc-data-model-2.0/#status>
#[serde_as]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Status {
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    pub id: Option<Url>,
    #[serde(rename = "type")]
    #[serde_as(as = "OneOrMany<_, PreferOne>")]
    pub status_type: Vec<String>,
}
/// <https://www.w3.org/TR/vc-data-model-2.0/#data-schemas>
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct CredentialSchema {
    pub id: Url,
    #[serde(rename = "type")]
    pub schema_type: String,
}

/// <https://www.w3.org/TR/vc-data-integrity/#proofs>
#[serde_as]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Proof {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Url>,
    #[serde(rename = "type")]
    pub proof_type: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "verificationMethod", skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptosuite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,
    #[serde_as(as = "Option<OneOrMany<_, PreferOne>>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(rename = "proofValue")]
    proof_value: String,
    #[serde(rename = "previousProof", skip_serializing_if = "Option::is_none")]
    pub previous_proof: Option<String>,
    #[serde_as(as = "Option<OneOrMany<_, PreferOne>>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Vec<String>>,
}

/// W3C Data Integrity cryptosuite identifiers this library signs with and can verify.
/// Both canonicalize with JCS (RFC 8785); the curve/algorithm is determined by the key.
pub(crate) const EDDSA_JCS_2022_CRYPTOSUITE: &str = "eddsa-jcs-2022";
pub(crate) const ECDSA_JCS_2019_CRYPTOSUITE: &str = "ecdsa-jcs-2019";

impl Proof {
    /// Construct a default data-integrity proof for the given `cryptosuite`, carrying the
    /// multibase-encoded `proof_value`.
    fn new_data_integrity(cryptosuite: &str, proof_value: String) -> Self {
        Proof {
            id: None,
            proof_type: "DataIntegrityProof".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            verification_method: None,
            cryptosuite: Some(cryptosuite.to_string()),
            created: None,
            expires: None,
            domain: None,
            challenge: None,
            proof_value,
            previous_proof: None,
            nonce: None,
        }
    }

    /// Set the ID of the proof
    pub fn set_id(mut self, id: Url) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the type of the proof
    pub fn set_proof_type(mut self, proof_type: String) -> Self {
        self.proof_type = proof_type;
        self
    }

    /// Set the proofPurpose of the proof
    pub fn set_proof_purpose(mut self, proof_purpose: String) -> Self {
        self.proof_purpose = proof_purpose;
        self
    }

    /// Set the verificationMethod of the proof
    pub fn set_verification_method(mut self, verification_method: String) -> Self {
        self.verification_method = Some(verification_method);
        self
    }

    /// Set the cryptosuite of the proof
    pub fn set_crypto_suite(mut self, cryptosuite: String) -> Self {
        self.cryptosuite = Some(cryptosuite);
        self
    }

    /// Set the validFrom timestamp of the proof
    pub fn set_created(mut self, created: DateTime<Utc>) -> Self {
        self.created = Some(created);
        self
    }

    /// Set the validUntil timestamp of the proof
    pub fn set_expires(mut self, expires: DateTime<Utc>) -> Self {
        self.expires = Some(expires);
        self
    }

    /// Set the domain of the proof
    pub fn set_domain(mut self, domain: Vec<String>) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Set the challenge of the proof
    pub fn set_challenge(mut self, challenge: String) -> Self {
        self.challenge = Some(challenge);
        self
    }

    /// Set the previousProof of the proof
    pub fn set_previous_proof(mut self, previous_proof: String) -> Self {
        self.previous_proof = Some(previous_proof);
        self
    }

    /// Set the nonce of the proof
    pub fn set_nonce(mut self, nonce: Vec<String>) -> Self {
        self.nonce = Some(nonce);
        self
    }
}

/// Where a JSON Schema used to validate a credential's `credentialSubject` comes from.
///
/// Passing this to [UnsignedVerifiableCredential::validate] /
/// [VerifiableCredential::validate] keeps schema validation a separate, composable
/// step from signing and verification, rather than spawning a method per schema source.
#[derive(Debug, Clone)]
pub enum SchemaSource<'a> {
    /// Do not perform any schema validation.
    None,
    /// Validate against an in-memory JSON Schema document.
    Inline(&'a Value),
    /// Fetch the JSON Schema from a URL, then validate. Not available on `wasm32`.
    #[cfg(not(target_arch = "wasm32"))]
    Url(&'a str),
}

impl SchemaSource<'_> {
    /// Resolve the schema to a concrete JSON document, fetching it over HTTP if necessary.
    /// Returns `None` when no validation is requested.
    fn resolve(&self) -> Result<Option<Value>, VcError> {
        match self {
            SchemaSource::None => Ok(None),
            SchemaSource::Inline(schema) => Ok(Some(Value::clone(schema))),
            #[cfg(not(target_arch = "wasm32"))]
            SchemaSource::Url(url) => {
                let schema_text = reqwest::blocking::get(*url)?.text()?;
                let schema: Value = serde_json::from_str(&schema_text)?;
                Ok(Some(schema))
            }
        }
    }
}

/// Validate a `credentialSubject` against a [SchemaSource].
fn validate_subject(subject: &Value, schema: &SchemaSource) -> Result<(), VcError> {
    if let Some(schema) = schema.resolve()? {
        if !jsonschema::is_valid(&schema, subject) {
            return Err(VcError::SchemaMismatch);
        }
    }
    Ok(())
}

impl UnsignedVerifiableCredential {
    /// Start building a credential from its required fields (`@context`, `type`,
    /// `issuer`, `credentialSubject`). Chain optional setters on the returned
    /// [UnsignedVerifiableCredentialBuilder], then call `.build()`.
    pub fn builder(
        context: Vec<Url>,
        credential_type: Vec<String>,
        issuer: Issuer,
        credential_subject: Value,
    ) -> UnsignedVerifiableCredentialBuilder {
        UnsignedVerifiableCredentialBuilder {
            inner: UnsignedVerifiableCredential {
                context,
                id: None,
                credential_type,
                name: None,
                description: None,
                issuer,
                credential_subject,
                valid_from: None,
                valid_until: None,
                credential_status: None,
                credential_schema: None,
            },
        }
    }

    /// Validate this credential's `credentialSubject` against a [SchemaSource].
    ///
    /// Call this before [sign](UnsignedVerifiableCredential::sign) when you need
    /// schema validation, e.g. `vc.validate(&schema)?; vc.sign(key)?`.
    pub fn validate(&self, schema: &SchemaSource) -> Result<(), VcError> {
        validate_subject(&self.credential_subject, schema)
    }

    /// The exact bytes that are signed and verified: the credential serialized with
    /// JCS canonicalization (RFC 8785), as required by the VC Data Integrity JSON
    /// cryptosuite. Canonicalizing makes the signed representation deterministic and
    /// independent of map iteration order or JSON-library quirks, so a signature
    /// survives a serialize/deserialize round-trip and is portable across
    /// implementations. Without it, the unordered `additional_properties` maps on
    /// `issuer`/`holder` objects would serialize inconsistently and break verification.
    fn signing_payload(&self) -> Result<Vec<u8>, VcError> {
        Ok(serde_jcs::to_vec(self)?)
    }

    /// Sign the Verifiable Credential with a [SigningKey], producing a
    /// [VerifiableCredential] with a `DataIntegrityProof` whose `cryptosuite` and
    /// `proofValue` match the key's algorithm (Ed25519 → `eddsa-jcs-2022`, ECDSA P-256/
    /// P-384 → `ecdsa-jcs-2019`). The signature is taken over the JCS-canonical credential
    /// and stored as a multibase (base58btc) `proofValue`.
    ///
    /// This performs no schema validation; call
    /// [validate](UnsignedVerifiableCredential::validate) first if you need it.
    pub fn sign(self, signing_key: &SigningKey) -> Result<VerifiableCredential, VcError> {
        let message = self.signing_payload()?;
        let signature = signing_key.sign_message(&message);
        let proof = Proof::new_data_integrity(
            signing_key.cryptosuite(),
            multibase::encode(Base::Base58Btc, signature),
        );

        Ok(VerifiableCredential {
            unsigned: self,
            proof,
        })
    }
}

impl VerifiableCredential {
    /// Removes the proof and returns the [UnsignedVerifiableCredential]
    pub fn to_unsigned(self) -> UnsignedVerifiableCredential {
        self.unsigned
    }

    /// Validate the embedded `credentialSubject` against a [SchemaSource].
    ///
    /// Call this alongside [verify](VerifiableCredential::verify) when you need
    /// schema validation, e.g. `vc.validate(&schema)?; vc.verify(key)?`.
    pub fn validate(&self, schema: &SchemaSource) -> Result<(), VcError> {
        self.unsigned.validate(schema)
    }

    /// Verifies the contents of a Verifiable Credential against a [VerifyingKey]
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), VcError> {
        let now = Utc::now();

        // Check if the current timestamp is within the validity period
        if let Some(valid_from) = self.unsigned.valid_from {
            if now < valid_from {
                return Err(VcError::NotYetValid);
            }
        }
        if let Some(valid_until) = self.unsigned.valid_until {
            if now > valid_until {
                return Err(VcError::Expired);
            }
        }

        // Reject any cryptosuite this library does not implement, rather than silently
        // applying the wrong algorithm. Both supported suites canonicalize with JCS; the
        // key's algorithm selects the actual verification (see VerifyingKey::verify_message).
        match self.proof.cryptosuite.as_deref() {
            Some(EDDSA_JCS_2022_CRYPTOSUITE) | Some(ECDSA_JCS_2019_CRYPTOSUITE) => {}
            other => {
                return Err(VcError::UnsupportedCryptosuite(
                    other.unwrap_or("(none)").to_string(),
                ))
            }
        }

        let message = self.unsigned.signing_payload()?;
        let (_, signature) = multibase::decode(&self.proof.proof_value)
            .map_err(|e| VcError::ProofDecode(e.to_string()))?;

        verifying_key.verify_message(&message, &signature)
    }
}

/// A signature algorithm supported by the toolkit. Each maps to a W3C Data Integrity
/// cryptosuite: [`Algorithm::Ed25519`] → `eddsa-jcs-2022`; [`Algorithm::P256`] and
/// [`Algorithm::P384`] → `ecdsa-jcs-2019`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Algorithm {
    /// Ed25519 (EdDSA).
    Ed25519,
    /// ECDSA over NIST P-256 (a.k.a. secp256r1 / ES256).
    P256,
    /// ECDSA over NIST P-384 (a.k.a. secp384r1 / ES384).
    P384,
}

impl Algorithm {
    fn cryptosuite(self) -> &'static str {
        match self {
            Algorithm::Ed25519 => EDDSA_JCS_2022_CRYPTOSUITE,
            Algorithm::P256 | Algorithm::P384 => ECDSA_JCS_2019_CRYPTOSUITE,
        }
    }
}

/// A private signing key for one of the supported [Algorithm]s, used to
/// [sign](UnsignedVerifiableCredential::sign) credentials.
///
/// A distinct type from [VerifyingKey] so the two cannot be swapped by accident.
#[derive(Clone)]
pub enum SigningKey {
    /// Ed25519 signing key.
    Ed25519(DalekSigningKey),
    /// ECDSA P-256 signing key.
    P256(p256::ecdsa::SigningKey),
    /// ECDSA P-384 signing key.
    P384(p384::ecdsa::SigningKey),
}

/// A public verifying key for one of the supported [Algorithm]s, used to
/// [verify](VerifiableCredential::verify) credentials. See [SigningKey] for why this is a
/// distinct type.
#[derive(Clone)]
pub enum VerifyingKey {
    /// Ed25519 verifying key.
    Ed25519(DalekVerifyingKey),
    /// ECDSA P-256 verifying key.
    P256(p256::ecdsa::VerifyingKey),
    /// ECDSA P-384 verifying key.
    P384(p384::ecdsa::VerifyingKey),
}

impl SigningKey {
    /// Construct an **Ed25519** signing key from exactly 32 seed bytes. For other
    /// algorithms use [from_pkcs8_pem](SigningKey::from_pkcs8_pem) or
    /// [generate_keypair_for].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VcError> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| VcError::InvalidPrivateKeyLength)?;
        Ok(Self::Ed25519(DalekSigningKey::from_bytes(&array)))
    }

    /// Parse a PKCS#8 PEM private key, dispatching on its algorithm (Ed25519, P-256, or
    /// P-384).
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, VcError> {
        use ed25519_dalek::pkcs8::DecodePrivateKey as _;

        if let Ok(k) = DalekSigningKey::from_pkcs8_pem(pem) {
            return Ok(Self::Ed25519(k));
        }
        if let Ok(k) = p256::ecdsa::SigningKey::from_pkcs8_pem(pem) {
            return Ok(Self::P256(k));
        }
        if let Ok(k) = p384::ecdsa::SigningKey::from_pkcs8_pem(pem) {
            return Ok(Self::P384(k));
        }
        Err(VcError::KeyParse(
            "PKCS#8 PEM is not a supported Ed25519/P-256/P-384 private key".to_string(),
        ))
    }

    /// The signature algorithm of this key.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            SigningKey::Ed25519(_) => Algorithm::Ed25519,
            SigningKey::P256(_) => Algorithm::P256,
            SigningKey::P384(_) => Algorithm::P384,
        }
    }

    /// The raw private-key bytes (Ed25519: 32-byte seed; ECDSA: the big-endian scalar).
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            SigningKey::Ed25519(k) => k.to_bytes().to_vec(),
            SigningKey::P256(k) => k.to_bytes().as_slice().to_vec(),
            SigningKey::P384(k) => k.to_bytes().as_slice().to_vec(),
        }
    }

    /// The Data Integrity cryptosuite identifier produced when signing with this key.
    pub(crate) fn cryptosuite(&self) -> &'static str {
        self.algorithm().cryptosuite()
    }

    /// The [VerifyingKey] corresponding to this signing key.
    pub fn verifying_key(&self) -> VerifyingKey {
        match self {
            SigningKey::Ed25519(k) => VerifyingKey::Ed25519(k.verifying_key()),
            SigningKey::P256(k) => VerifyingKey::P256(*k.verifying_key()),
            SigningKey::P384(k) => VerifyingKey::P384(*k.verifying_key()),
        }
    }

    /// Sign `message`, returning the raw signature bytes (Ed25519: 64 bytes; ECDSA:
    /// fixed-size IEEE-P1363 `r‖s`).
    pub(crate) fn sign_message(&self, message: &[u8]) -> Vec<u8> {
        match self {
            SigningKey::Ed25519(k) => k.sign(message).to_bytes().to_vec(),
            SigningKey::P256(k) => {
                let sig: p256::ecdsa::Signature = k.sign(message);
                sig.to_bytes().as_slice().to_vec()
            }
            SigningKey::P384(k) => {
                let sig: p384::ecdsa::Signature = k.sign(message);
                sig.to_bytes().as_slice().to_vec()
            }
        }
    }
}

impl VerifyingKey {
    /// Construct an **Ed25519** verifying key from exactly 32 bytes. For other algorithms
    /// use [from_pem](VerifyingKey::from_pem).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VcError> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| VcError::InvalidPublicKeyLength)?;
        Ok(Self::Ed25519(
            DalekVerifyingKey::from_bytes(&array).map_err(VcError::InvalidPublicKey)?,
        ))
    }

    /// Parse a SubjectPublicKeyInfo PEM (`-----BEGIN PUBLIC KEY-----`), dispatching on the
    /// key's algorithm OID — Ed25519, ECDSA P-256, or ECDSA P-384. This is the form
    /// returned as `publicKeyPem` in DID documents.
    pub fn from_pem(pem: &str) -> Result<Self, VcError> {
        let parsed = pem::parse(pem).map_err(|e| VcError::KeyParse(e.to_string()))?;
        Self::from_spki_der(parsed.contents())
    }

    /// Parse a DER-encoded SubjectPublicKeyInfo, dispatching on the algorithm OID.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, VcError> {
        use spki::der::Decode;

        let spki = spki::SubjectPublicKeyInfoRef::from_der(der)
            .map_err(|e| VcError::KeyParse(e.to_string()))?;
        let key_bytes = spki.subject_public_key.raw_bytes();

        match spki.algorithm.oid.to_string().as_str() {
            // id-Ed25519
            "1.3.101.112" => {
                let array: [u8; 32] = key_bytes
                    .try_into()
                    .map_err(|_| VcError::KeyParse("Ed25519 public key must be 32 bytes".into()))?;
                Ok(Self::Ed25519(
                    DalekVerifyingKey::from_bytes(&array).map_err(VcError::InvalidPublicKey)?,
                ))
            }
            // id-ecPublicKey: curve is named in the algorithm parameters
            "1.2.840.10045.2.1" => {
                let curve = spki
                    .algorithm
                    .parameters_oid()
                    .map_err(|e| VcError::KeyParse(e.to_string()))?;
                match curve.to_string().as_str() {
                    // secp256r1 / prime256v1
                    "1.2.840.10045.3.1.7" => Ok(Self::P256(
                        p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                            .map_err(|e| VcError::KeyParse(e.to_string()))?,
                    )),
                    // secp384r1
                    "1.3.132.0.34" => Ok(Self::P384(
                        p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                            .map_err(|e| VcError::KeyParse(e.to_string()))?,
                    )),
                    other => Err(VcError::UnsupportedKeyType(format!("EC curve {other}"))),
                }
            }
            other => Err(VcError::UnsupportedKeyType(format!(
                "SPKI algorithm OID {other}"
            ))),
        }
    }

    /// The signature algorithm of this key.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            VerifyingKey::Ed25519(_) => Algorithm::Ed25519,
            VerifyingKey::P256(_) => Algorithm::P256,
            VerifyingKey::P384(_) => Algorithm::P384,
        }
    }

    /// The raw public-key bytes (Ed25519: 32 bytes; ECDSA: the uncompressed SEC1 point).
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            VerifyingKey::Ed25519(k) => k.to_bytes().to_vec(),
            VerifyingKey::P256(k) => k.to_encoded_point(false).as_bytes().to_vec(),
            VerifyingKey::P384(k) => k.to_encoded_point(false).as_bytes().to_vec(),
        }
    }

    /// Verify `signature` over `message` using this key's algorithm.
    pub(crate) fn verify_message(&self, message: &[u8], signature: &[u8]) -> Result<(), VcError> {
        match self {
            VerifyingKey::Ed25519(k) => {
                let sig = Signature::from_slice(signature)
                    .map_err(|e| VcError::MalformedSignature(e.to_string()))?;
                k.verify(message, &sig)
                    .map_err(|e| VcError::SignatureVerificationFailed(e.to_string()))
            }
            VerifyingKey::P256(k) => {
                let sig = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|e| VcError::MalformedSignature(e.to_string()))?;
                k.verify(message, &sig)
                    .map_err(|e| VcError::SignatureVerificationFailed(e.to_string()))
            }
            VerifyingKey::P384(k) => {
                let sig = p384::ecdsa::Signature::from_slice(signature)
                    .map_err(|e| VcError::MalformedSignature(e.to_string()))?;
                k.verify(message, &sig)
                    .map_err(|e| VcError::SignatureVerificationFailed(e.to_string()))
            }
        }
    }
}

// Redact the secret in Debug output so it can't leak into logs.
impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey::{:?}([REDACTED])", self.algorithm())
    }
}

/// A key pair produced by [generate_keypair] / [generate_keypair_for].
#[derive(Clone)]
pub struct KeyPair {
    /// The private key used to sign credentials.
    pub signing_key: SigningKey,
    /// The public key used to verify credentials.
    pub verifying_key: VerifyingKey,
}

/// Generate a new Ed25519 [KeyPair]. For another algorithm use [generate_keypair_for].
pub fn generate_keypair() -> KeyPair {
    generate_keypair_for(Algorithm::Ed25519)
}

/// Generate a new [KeyPair] for the given [Algorithm].
pub fn generate_keypair_for(algorithm: Algorithm) -> KeyPair {
    let mut csprng = OsRng;
    let signing_key = match algorithm {
        Algorithm::Ed25519 => SigningKey::Ed25519(DalekSigningKey::generate(&mut csprng)),
        Algorithm::P256 => SigningKey::P256(p256::ecdsa::SigningKey::random(&mut csprng)),
        Algorithm::P384 => SigningKey::P384(p384::ecdsa::SigningKey::random(&mut csprng)),
    };
    let verifying_key = signing_key.verifying_key();
    KeyPair {
        signing_key,
        verifying_key,
    }
}
