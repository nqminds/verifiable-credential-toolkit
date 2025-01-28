use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::formats::PreferOne;
use serde_with::{serde_as, OneOrMany};

/// A Verifiable Credential as defined by the W3C Verifiable Credentials Data Model v2.0 - <https://www.w3.org/TR/vc-data-model-2.0>
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct VerifiableCredential {
    /// <https://www.w3.org/TR/vc-data-model-2.0/#contexts>
    #[serde(rename = "@context")]
    context: Vec<String>,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#identifiers>
    id: Option<String>,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#types>
    #[serde(rename = "type")]
    #[serde_as(as = "OneOrMany<_, PreferOne>")]
    credential_type: Vec<String>,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#names-and-descriptions>
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<LanguageValue>,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#names-and-descriptions>
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<LanguageValue>,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#issuer>
    issuer: Issuer,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#credential-subject>
    #[serde(rename = "credentialSubject")]
    credential_subject: Value,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#validity-period>
    #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none")]
    valid_from: Option<DateTime<Utc>>,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#validity-period>
    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
    valid_until: Option<DateTime<Utc>>,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#status>
    #[serde(rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
    credential_status: Option<Status>,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#data-schemas>
    #[serde_as(as = "Option<OneOrMany<_, PreferOne>>")]
    #[serde(rename = "credentialSchema", skip_serializing_if = "Option::is_none")]
    credential_schema: Option<Vec<CredentialSchema>>,
    /// <https://www.w3.org/TR/vc-data-model-2.0/#securing-mechanisms>
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<Proof>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum Issuer {
    String(String),
    Object(IssuerObject),
}

/// <https://www.w3.org/TR/vc-data-model-2.0/#issuer>
#[derive(Serialize, Deserialize, Debug)]
struct IssuerObject {
    id: String,
    #[serde(flatten)]
    additional_properties: Option<HashMap<String, Value>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum LanguageValue {
    PlainString(String),
    LanguageObject(LanguageObject),
}

/// <https://www.w3.org/TR/vc-data-model-2.0/#language-and-base-direction>
#[derive(Serialize, Deserialize, Debug)]
struct LanguageObject {
    #[serde(rename = "@value")]
    value: String,
    #[serde(rename = "@language", skip_serializing_if = "Option::is_none")]
    language: Option<String>,
    #[serde(rename = "@direction", skip_serializing_if = "Option::is_none")]
    direction: Option<String>,
}
/// <https://www.w3.org/TR/vc-data-model-2.0/#status>
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct Status {
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(rename = "type")]
    #[serde_as(as = "OneOrMany<_, PreferOne>")]
    status_type: Vec<String>,
}
/// <https://www.w3.org/TR/vc-data-model-2.0/#data-schemas>
#[derive(Serialize, Deserialize, Debug)]
struct CredentialSchema {
    id: String,
    #[serde(rename = "type")]
    schema_type: String,
}

/// <https://www.w3.org/TR/vc-data-integrity/#proofs>
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that a valid Verifiable Credential can be deserialized
    #[test]
    fn valid_vc_deserializes() {
        let vc: VerifiableCredential =
            serde_json::from_str(include_str!("../test_data/henryTrustPhone.json"))
                .expect("Failed to deserialize JSON");

        assert!(serde_json::to_string(&vc).is_ok());
    }

    /// Test that an invalid Verifiable Credential fails to deserialize
    #[test]
    fn invalid_vc_fails_to_deserialize() {
        let vc: Result<VerifiableCredential, _> =
            serde_json::from_str(include_str!("../test_data/henryTrustPhoneInvalid.json"));

        assert!(vc.is_err());
    }

    /// Test that the OneOrMany<_, PreferOne> serde_as helper works as expected
    #[test]
    fn one_or_many_test() {
        let vc: VerifiableCredential =
            serde_json::from_str(include_str!("../test_data/unsigned_one_or_many.json"))
                .expect("Failed to deserialize JSON");

        // Test that the single string is deserialized correctly
        assert!(serde_json::to_string(&vc).is_ok());

        let json_vc = serde_json::to_string(&vc).unwrap();

        // Test that the vec is correctly serialized into a single string
        assert!(json_vc.contains(r#""type":"VerifiableCredential""#));
    }
}
