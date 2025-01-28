use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::serde_as;

#[derive(Serialize, Deserialize, Debug)]
#[serde_as]
#[serde(deny_unknown_fields)]
struct VerifiableCredential {
    #[serde(rename = "@context")]
    context: Vec<String>,
    id: Option<String>,
    #[serde(rename = "type")]
    #[serde_as(as = "OneOrMany<_, PreferOne>")]
    credential_type: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<LanguageValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<LanguageValue>,
    issuer: Issuer,
    #[serde(rename = "credentialSubject")]
    credential_subject: Value,
    #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none")]
    valid_from: Option<DateTime<Utc>>,
    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
    valid_until: Option<DateTime<Utc>>,
    #[serde(rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
    credential_status: Option<Status>,
    #[serde_as(as = "OneOrMany<_, PreferOne>")]
    #[serde(rename = "credentialSchema", skip_serializing_if = "Option::is_none")]
    credential_schema: Option<CredentialSchema>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<Proof>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum Issuer {
    String(String),
    Object(IssuerObject),
}

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

#[derive(Serialize, Deserialize, Debug)]
struct LanguageObject {
    #[serde(rename = "@value")]
    value: String,
    #[serde(rename = "@language", skip_serializing_if = "Option::is_none")]
    language: Option<String>,
    #[serde(rename = "@direction", skip_serializing_if = "Option::is_none")]
    direction: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde_as]
struct Status {
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(rename = "type")]
    #[serde_as(as = "OneOrMany<_, PreferOne>")]
    status_type: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde_as]
struct CredentialSchema {
    id: String,
    #[serde(rename = "type")]
    schema_type: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde_as]
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
    #[serde_as(as = "OneOrMany<_, PreferOne>")]
    domain: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge: Option<String>,
    #[serde(rename = "proofValue")]
    proof_value: String,
    #[serde(rename = "previousProof", skip_serializing_if = "Option::is_none")]
    previous_proof: Option<String>,
    #[serde_as(as = "OneOrMany<_, PreferOne>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_vc_deserializes() {
        let vc: VerifiableCredential =
            serde_json::from_str(include_str!("../test_data/henryTrustPhone.json"))
                .expect("Failed to deserialize JSON");

        assert!(serde_json::to_string(&vc).is_ok());
    }

    #[test]
    fn invalid_vc_fails_to_deserialize() {
        let vc: Result<VerifiableCredential, _> =
            serde_json::from_str(include_str!("../test_data/henryTrustPhoneInvalid.json"));

        assert!(vc.is_err());
    }
}
