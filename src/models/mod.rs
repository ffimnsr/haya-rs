#![allow(unused_imports)]

mod authorization_code_claims;
mod client;
mod oauth_access_token;
mod oauth_authorization_code;
mod oauth_authorization_server_metadata;
mod oauth_refresh_token;
mod standard_token_claims;

pub(crate) use authorization_code_claims::*;
pub(crate) use client::*;
pub(crate) use oauth_access_token::*;
pub(crate) use oauth_authorization_code::*;
pub(crate) use oauth_authorization_server_metadata::*;
pub(crate) use oauth_refresh_token::*;
pub(crate) use standard_token_claims::*;

use postgres_types::ToSql;

pub(crate) type Parameter<'a> = &'a (dyn ToSql + Sync);
