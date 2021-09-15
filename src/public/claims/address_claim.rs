//! This module contains the structure for address claims.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct AddressClaim {
    /// Full mailing address, formatted for display or use on a mailing label.
    /// This field MAY contain multiple lines, separated by newlines. Newlines
    /// can be represented either as a carriage return/line feed pair ("\r\n")
    /// or as a single line feed character ("\n").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,

    /// Full street address component, which MAY include house number, street
    /// name, Post Office Box, and multi-line extended street address
    /// information. This field MAY contain multiple lines, separated by
    /// newlines. Newlines can be represented either as a carriage return/line
    /// feed pair ("\r\n") or as a single line feed character ("\n").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,

    /// City or locality component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,

    /// State, province, prefecture, or region component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// Zip code or postal code component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,

    /// Country name component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}
