use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::formats::PreferOne;
use serde_with::{serde_as, OneOrMany};
use std::collections::HashMap;
use url::Url;

pub mod bindings;
pub mod proto_schemas;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

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
pub enum Holder {
    Url(Url),
    Object(HolderObject),
}

/// <https://www.w3.org/TR/vc-data-model-2.0/#holder>
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct HolderObject {
    id: Url,
    #[serde(flatten)]
    additional_properties: Option<HashMap<String, Value>>,
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
    id: Url,
    #[serde(flatten)]
    additional_properties: Option<HashMap<String, Value>>,
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
    value: String,
    #[serde(rename = "@language", skip_serializing_if = "Option::is_none")]
    language: Option<String>,
    #[serde(rename = "@direction", skip_serializing_if = "Option::is_none")]
    direction: Option<String>,
}
/// <https://www.w3.org/TR/vc-data-model-2.0/#status>
#[serde_as]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Status {
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    id: Option<Url>,
    #[serde(rename = "type")]
    #[serde_as(as = "OneOrMany<_, PreferOne>")]
    status_type: Vec<String>,
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
    fn resolve(&self) -> Result<Option<Value>, Box<dyn std::error::Error>> {
        match self {
            SchemaSource::None => Ok(None),
            SchemaSource::Inline(schema) => Ok(Some(Value::clone(schema))),
            #[cfg(not(target_arch = "wasm32"))]
            SchemaSource::Url(url) => {
                let response = reqwest::blocking::get(*url)
                    .map_err(|e| format!("Failed to fetch schema from URL: {}", e))?;
                let schema_text = response
                    .text()
                    .map_err(|e| format!("Failed to read schema text: {}", e))?;
                let schema: Value = serde_json::from_str(&schema_text)
                    .map_err(|e| format!("Failed to parse schema JSON: {}", e))?;
                Ok(Some(schema))
            }
        }
    }
}

/// Validate a `credentialSubject` against a [SchemaSource].
fn validate_subject(
    subject: &Value,
    schema: &SchemaSource,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(schema) = schema.resolve()? {
        if !jsonschema::is_valid(&schema, subject) {
            return Err("Credential subject does not match schema".into());
        }
    }
    Ok(())
}

/// Parse a 32-byte Ed25519 signing key from arbitrary byte input.
fn signing_key_from_bytes(
    private_key: impl AsRef<[u8]>,
) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let private_key_array: [u8; 32] = private_key.as_ref().try_into().map_err(|_| {
        "Invalid private key length: expected 32 bytes, but received a different size."
    })?;
    Ok(SigningKey::from_bytes(&private_key_array))
}

impl UnsignedVerifiableCredential {
    /// Validate this credential's `credentialSubject` against a [SchemaSource].
    ///
    /// Call this before [sign](UnsignedVerifiableCredential::sign) when you need
    /// schema validation, e.g. `vc.validate(&schema)?; vc.sign(key)?`.
    pub fn validate(&self, schema: &SchemaSource) -> Result<(), Box<dyn std::error::Error>> {
        validate_subject(&self.credential_subject, schema)
    }

    /// Sign the Verifiable Credential with an Ed25519 private key, producing a
    /// [VerifiableCredential] with a default proof and a computed `proofValue`.
    ///
    /// This performs no schema validation; call
    /// [validate](UnsignedVerifiableCredential::validate) first if you need it.
    pub fn sign(
        self,
        private_key: impl AsRef<[u8]>,
    ) -> Result<VerifiableCredential, Box<dyn std::error::Error>> {
        let signing_key = signing_key_from_bytes(private_key)?;
        let message = serde_json::to_string(&self)
            .map_err(|e| format!("Failed to serialize credential during sign: {}", e))?;
        let signature = signing_key.sign(message.as_bytes());
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
    pub fn validate(&self, schema: &SchemaSource) -> Result<(), Box<dyn std::error::Error>> {
        self.unsigned.validate(schema)
    }

    /// Verifies the contents of a Verifiable Credential against a public key
    pub fn verify(&self, public_key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let now = Utc::now();

        // Check if the current timestamp is within the validity period
        if let Some(valid_from) = self.unsigned.valid_from {
            if now < valid_from {
                return Err("The credential is not yet valid (validFrom check failed).".into());
            }
        }
        if let Some(valid_until) = self.unsigned.valid_until {
            if now > valid_until {
                return Err("The credential has expired (validUntil check failed).".into());
            }
        }

        let message = serde_json::to_string(&self.unsigned).map_err(|e| {
            format!(
                "Failed to serialize unsigned credential during verification: {}",
                e
            )
        })?;
        let proof_bytes = BASE64_STANDARD
            .decode(&self.proof.proof_value)
            .map_err(|e| format!("Failed to decode proof value from base64: {}", e))?;
        let signature = Signature::from_slice(&proof_bytes)
            .map_err(|e| format!("Failed to create signature from proof bytes: {}", e))?;
        let public_key_array: [u8; 32] = public_key.try_into().map_err(|_| {
            "Invalid public key length: expected 32 bytes, but received a different size."
        })?;
        let public_key = VerifyingKey::from_bytes(&public_key_array).map_err(|e| {
            format!(
                "Failed to create verifying key from public key bytes: {}",
                e
            )
        })?;

        public_key
            .verify(message.as_bytes(), &signature)
            .map_err(|e| format!("Failed to verify the credential signature: {}", e))?;
        Ok(())
    }
}

/// Generate a new Ed25519 keypair tuple. First is the signing key, second is the verifying key.
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let signing_key_bytes = signing_key.to_bytes();

    let verifying_key_bytes = verifying_key.to_bytes();

    (signing_key_bytes, verifying_key_bytes)
}
