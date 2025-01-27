use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::serde_as;

#[derive(Serialize, Deserialize, Debug)]
#[serde_as]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: Option<String>,
    #[serde(rename = "type")]
    #[serde_as(as = "OneOrMany<_, PreferOne>")]
    pub credential_type: Vec<String>,
    pub name: Option<LanguageValue>,
    pub description: Option<LanguageValue>,
    pub issuer: Issuer,
    pub credential_subject: Value,
    #[serde(rename = "validFrom")]
    pub valid_from: Option<DateTime<Utc>>,
    #[serde(rename = "validUntil")]
    pub valid_until: Option<DateTime<Utc>>,
    pub status: Option<Status>,
    pub credential_schema: Option<CredentialSchema>,
    pub refresh_service: Option<RefreshService>,
    pub terms_of_use: Option<Vec<TermsOfUse>>,
    pub evidence: Option<Vec<Evidence>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Issuer {
    String(String),
    Object(IssuerObject),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IssuerObject {
    pub id: String,
    #[serde(flatten)]
    pub additional_properties: Option<HashMap<String, Value>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum LanguageValue {
    PlainString(String),
    LanguageObject(LanguageObject),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LanguageObject {
    #[serde(rename = "@value")]
    pub value: String,
    #[serde(rename = "@language")]
    pub language: Option<String>,
    #[serde(rename = "@direction")]
    pub direction: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Status {
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub status_type: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialSchema {
    pub id: String,
    #[serde(rename = "type")]
    pub schema_type: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RefreshService {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TermsOfUse {
    pub id: String,
    #[serde(rename = "type")]
    pub terms_type: String,
    // Additional properties can be added here
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Evidence {
    pub id: String,
    #[serde(rename = "type")]
    pub evidence_type: String,
    // Additional properties can be added here
}
