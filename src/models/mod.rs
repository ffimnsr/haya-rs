mod client;
mod oauth_authorization_code;
mod oauth_authorization_server_metadata;
mod authorization_code_claims;
mod standard_token_claims;

pub(crate) use client::*;
pub(crate) use oauth_authorization_code::*;
pub(crate) use oauth_authorization_server_metadata::*;
pub(crate) use authorization_code_claims::*;
pub(crate) use standard_token_claims::*;

use postgres_types::ToSql;

pub(crate) type Parameter<'a> = &'a (dyn ToSql + Sync);
