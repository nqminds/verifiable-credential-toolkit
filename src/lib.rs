use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::{DateTime, Utc};
use ring::signature::Ed25519KeyPair;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::formats::PreferOne;
use serde_with::{serde_as, OneOrMany};
use std::collections::HashMap;

/// A Verifiable Credential as defined by the W3C Verifiable Credentials Data Model v2.0 - <https://www.w3.org/TR/vc-data-model-2.0> WITHOUT the proof
#[serde_as]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct UnsignedVerifiableCredential {
    /// <https://www.w3.org/TR/vc-data-model-2.0/#contexts>
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#identifiers>
    pub id: Option<String>,
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
    unsigned: UnsignedVerifiableCredential,
    proof: Proof,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub enum Issuer {
    String(String),
    Object(IssuerObject),
}

/// <https://www.w3.org/TR/vc-data-model-2.0/#issuer>
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct IssuerObject {
    id: String,
    #[serde(flatten)]
    additional_properties: Option<HashMap<String, Value>>,
}

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
    id: Option<String>,
    #[serde(rename = "type")]
    #[serde_as(as = "OneOrMany<_, PreferOne>")]
    status_type: Vec<String>,
}
/// <https://www.w3.org/TR/vc-data-model-2.0/#data-schemas>
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct CredentialSchema {
    id: String,
    #[serde(rename = "type")]
    schema_type: String,
}

/// <https://www.w3.org/TR/vc-data-integrity/#proofs>
#[serde_as]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct Proof {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(rename = "type")]
    proof_type: String,
    #[serde(rename = "proofPurpose")]
    proof_purpose: String,
    #[serde(rename = "verificationMethod")]
    verification_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cryptosuite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<OneOrMany<_, PreferOne>>")]
    domain: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge: Option<String>,
    #[serde(rename = "proofValue")]
    proof_value: String,
    #[serde(rename = "previousProof", skip_serializing_if = "Option::is_none")]
    previous_proof: Option<String>,
    #[serde_as(as = "Option<OneOrMany<_, PreferOne>>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<Vec<String>>,
}

impl UnsignedVerifiableCredential {
    pub fn sign(
        self,
        private_key: &[u8],
    ) -> Result<VerifiableCredential, Box<dyn std::error::Error>> {
        let private_key = Ed25519KeyPair::from_pkcs8(private_key).map_err(|e| e.to_string())?;
        let proof_value = private_key.sign(self.id.as_ref().unwrap().as_bytes());

        let proof: Proof = Proof {
            id: None,
            proof_type: "Ed25519Signature2018".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            verification_method: None,
            cryptosuite: None,
            created: None,
            expires: None,
            domain: None,
            challenge: None,
            proof_value: BASE64_STANDARD.encode(proof_value.as_ref()),
            previous_proof: None,
            nonce: None,
        };

        Ok(VerifiableCredential {
            unsigned: self,
            proof,
        })
    }

    pub fn sign_with_schema_check(
        self,
        private_key: &[u8],
        schema: &str,
    ) -> Result<VerifiableCredential, Box<dyn std::error::Error>> {
        // Validate the credentialSubject against the provided schema
        let schema: Value = serde_json::from_str(schema)?;
        let credential_subject = &self.credential_subject;

        if !jsonschema::is_valid(&schema, credential_subject) {
            return Err("Credential subject does not match schema".into());
        }

        // Proceed with signing if validation is successful
        let private_key = Ed25519KeyPair::from_pkcs8(private_key).map_err(|e| e.to_string())?;
        let proof_value = private_key.sign(self.id.as_ref().unwrap().as_bytes());

        let proof: Proof = Proof {
            id: None,
            proof_type: "Ed25519Signature2018".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            verification_method: None,
            cryptosuite: None,
            created: None,
            expires: None,
            domain: None,
            challenge: None,
            proof_value: BASE64_STANDARD.encode(proof_value.as_ref()),
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
    pub fn to_unsigned(self) -> UnsignedVerifiableCredential {
        self.unsigned
    }
}
