use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{
    Signature, Signer, SigningKey as DalekSigningKey, Verifier, VerifyingKey as DalekVerifyingKey,
};
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

impl Proof {
    /// Construct a default Ed25519 proof carrying the given base64-encoded `proofValue`.
    fn new_ed25519(proof_value: String) -> Self {
        Proof {
            id: None,
            proof_type: "Ed25519Signature2018".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            verification_method: None,
            cryptosuite: None,
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

    /// Sign the Verifiable Credential with an Ed25519 [SigningKey], producing a
    /// [VerifiableCredential] with a default proof and a computed `proofValue`.
    ///
    /// This performs no schema validation; call
    /// [validate](UnsignedVerifiableCredential::validate) first if you need it.
    pub fn sign(self, signing_key: &SigningKey) -> Result<VerifiableCredential, VcError> {
        let dalek_key = DalekSigningKey::from_bytes(&signing_key.0);
        let message = self.signing_payload()?;
        let signature = dalek_key.sign(&message);
        let proof = Proof::new_ed25519(BASE64_STANDARD.encode(signature.to_bytes()));

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

        let message = self.unsigned.signing_payload()?;
        let proof_bytes = BASE64_STANDARD.decode(&self.proof.proof_value)?;
        let signature = Signature::from_slice(&proof_bytes).map_err(VcError::MalformedSignature)?;
        let dalek_key =
            DalekVerifyingKey::from_bytes(&verifying_key.0).map_err(VcError::InvalidPublicKey)?;

        dalek_key
            .verify(&message, &signature)
            .map_err(VcError::SignatureVerificationFailed)?;
        Ok(())
    }
}

/// A 32-byte Ed25519 private key, used to [sign](UnsignedVerifiableCredential::sign)
/// credentials.
///
/// A distinct type from [VerifyingKey] so the two cannot be swapped by accident —
/// passing a public key where a private key is expected (or vice versa) is a compile
/// error rather than a silent runtime failure.
#[derive(Clone)]
pub struct SigningKey([u8; 32]);

/// A 32-byte Ed25519 public key, used to [verify](VerifiableCredential::verify)
/// credentials. See [SigningKey] for why this is a distinct type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VerifyingKey([u8; 32]);

impl SigningKey {
    /// Construct a signing key from exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VcError> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| VcError::InvalidPrivateKeyLength)?;
        Ok(Self(array))
    }

    /// The raw 32-byte representation of the key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl VerifyingKey {
    /// Construct a verifying key from exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VcError> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| VcError::InvalidPublicKeyLength)?;
        Ok(Self(array))
    }

    /// The raw 32-byte representation of the key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for SigningKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<[u8; 32]> for VerifyingKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for SigningKey {
    type Error = VcError;
    fn try_from(bytes: &[u8]) -> Result<Self, VcError> {
        Self::from_bytes(bytes)
    }
}

impl TryFrom<&[u8]> for VerifyingKey {
    type Error = VcError;
    fn try_from(bytes: &[u8]) -> Result<Self, VcError> {
        Self::from_bytes(bytes)
    }
}

// Redact the secret in Debug output so it can't leak into logs.
impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey([REDACTED])")
    }
}

/// An Ed25519 key pair produced by [generate_keypair].
#[derive(Clone)]
pub struct KeyPair {
    /// The private key used to sign credentials.
    pub signing_key: SigningKey,
    /// The public key used to verify credentials.
    pub verifying_key: VerifyingKey,
}

/// Generate a new Ed25519 [KeyPair].
pub fn generate_keypair() -> KeyPair {
    let mut csprng = OsRng;
    let signing_key = DalekSigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    KeyPair {
        signing_key: SigningKey(signing_key.to_bytes()),
        verifying_key: VerifyingKey(verifying_key.to_bytes()),
    }
}
