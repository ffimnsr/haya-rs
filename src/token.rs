//! This module contains the basic structure for identity claims.

use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IdentityClaims {
  // Issuer identifier for the Issuer of the response
  #[serde(rename = "iss")]
  pub issuer: String,

  // Subject identifier
  #[serde(rename = "sub")]
  pub subject: String,

  // Audience(s) that this ID token is inteded for
  #[serde(rename = "aud")]
  pub audience: String,

  // Expiration time on or after which the ID Token MUST NOT be accepted for processing
  #[serde(rename = "exp")]
  pub expiration_time: usize,

  // Time at which the JWT was issued
  #[serde(rename = "iat")]
  pub issued_at_time: usize,

  // Time when the End-User authentication occurred
  pub auth_time: usize,

  // String value used to associate a Client session with an ID Token, and to mitigate replay attacks
  pub nonce: String,

  // String specifying an Authentication Context Class Reference value that identifies the Authentication Context Class that the authentication performed satisfied
  #[serde(rename = "acr")]
  pub auth_class_reference: Option<String>,

  // JSON array of strings that are identifiers for authentication methods used in the authentication
  #[serde(rename = "amr")]
  pub auth_methods_references: Option<Vec<String>>,

  // The party to which the ID Token was issued
  #[serde(rename = "azp")]
  pub authorized_party: Option<String>,
}
