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
    id: Url,
    #[serde(rename = "type")]
    schema_type: String,
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

impl UnsignedVerifiableCredential {
    /// Sign the Verifiable Credential with a private key. Creates a proof with default values and a custom proofValue.
    pub fn sign(
        self,
        private_key: impl AsRef<[u8]>,
    ) -> Result<VerifiableCredential, Box<dyn std::error::Error>> {
        let private_key_slice = private_key.as_ref();
        let private_key_array: [u8; 32] = private_key_slice.try_into().map_err(|_| {
            "Invalid private key length: expected 32 bytes, but received a different size."
        })?;
        let signing_key = SigningKey::from_bytes(&private_key_array);
        let message = serde_json::to_string(&self)
            .map_err(|e| format!("Failed to serialize credential during sign: {}", e))?
            .as_bytes()
            .to_vec();
        let signature = signing_key.sign(&message);

        let proof = Proof {
            id: None,
            proof_type: "Ed25519Signature2018".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            verification_method: None,
            cryptosuite: None,
            created: None,
            expires: None,
            domain: None,
            challenge: None,
            proof_value: BASE64_STANDARD.encode(signature.to_bytes()),
            previous_proof: None,
            nonce: None,
        };

        Ok(VerifiableCredential {
            unsigned: self,
            proof,
        })
    }

    /// Sign the Verifiable Credential with a private key. Creates a proof with default values and a custom proofValue. Also performs a JSON schema check on the credentialSubject.
    pub fn sign_with_schema_check(
        self,
        private_key: impl AsRef<[u8]>,
        schema: &str,
    ) -> Result<VerifiableCredential, Box<dyn std::error::Error>> {
        // Validate the credentialSubject against the provided schema
        let schema: Value =
            serde_json::from_str(schema).map_err(|e| format!("Failed to parse schema: {}", e))?;
        let credential_subject = &self.credential_subject;

        if !jsonschema::is_valid(&schema, credential_subject) {
            return Err("Credential subject does not match schema".into());
        }

        // Proceed with signing if validation is successful
        let private_key_slice = private_key.as_ref();
        let private_key_array: [u8; 32] = private_key_slice.try_into().map_err(|_| {
            "Invalid private key length: expected 32 bytes, but received a different size."
        })?;
        let signing_key = SigningKey::from_bytes(&private_key_array);
        let message = serde_json::to_string(&self)
            .map_err(|e| format!("Failed to serialize credential during sign: {}", e))?
            .as_bytes()
            .to_vec();
        let signature = signing_key.sign(&message);

        let proof = Proof {
            id: None,
            proof_type: "Ed25519Signature2018".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            verification_method: None,
            cryptosuite: None,
            created: None,
            expires: None,
            domain: None,
            challenge: None,
            proof_value: BASE64_STANDARD.encode(signature.to_bytes()),
            previous_proof: None,
            nonce: None,
        };

        Ok(VerifiableCredential {
            unsigned: self,
            proof,
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl UnsignedVerifiableCredential {
    /// Sign the Verifiable Credential with a private key. Creates a proof with default values and a custom proofValue. Also performs a JSON schema check on the credentialSubject. The schema is fetched from a URL.
    pub fn sign_with_schema_check_from_url(
        self,
        private_key: impl AsRef<[u8]>,
        schema_url: &str,
    ) -> Result<VerifiableCredential, Box<dyn std::error::Error>> {
        // Attempt to get the schema from the URL using reqwest

        let response = reqwest::blocking::get(schema_url)
            .map_err(|e| format!("Failed to fetch schema from URL: {}", e))?;
        let schema_text = response
            .text()
            .map_err(|e| format!("Failed to read schema text: {}", e))?;
        let schema: Value = serde_json::from_str(&schema_text)
            .map_err(|e| format!("Failed to parse schema JSON: {}", e))?;

        // Validate the credentialSubject against the schema
        let credential_subject = &self.credential_subject;
        if !jsonschema::is_valid(&schema, credential_subject) {
            return Err("Credential subject does not match schema".into());
        }

        // Proceed with signing if validation is successful
        let private_key_slice = private_key.as_ref();
        let private_key_array: [u8; 32] = private_key_slice.try_into().map_err(|_| {
            "Invalid private key length: expected 32 bytes, but received a different size."
        })?;
        let signing_key = SigningKey::from_bytes(&private_key_array);
        let message = serde_json::to_string(&self)
            .map_err(|e| format!("Failed to serialize credential during sign: {}", e))?
            .as_bytes()
            .to_vec();
        let signature = signing_key.sign(&message);

        let proof = Proof {
            id: None,
            proof_type: "Ed25519Signature2018".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            verification_method: None,
            cryptosuite: None,
            created: None,
            expires: None,
            domain: None,
            challenge: None,
            proof_value: BASE64_STANDARD.encode(signature.to_bytes()),
            previous_proof: None,
            nonce: None,
        };

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

    /// Verifies the contents of a Verifiable Credential against a public key
    pub fn verify(&self, public_key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
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
            "Invalid private key length: expected 32 bytes, but received a different size."
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
