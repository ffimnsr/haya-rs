#![allow(dead_code)]
pub(crate) const AUTHORIZATION_CODE_LIFETIME: i64 = 300;
pub(crate) const ACCESS_TOKEN_LIFETIME: i64 = 3600;
pub(crate) const REFRESH_TOKEN_LIFETIME: i64 = 1_209_600;

pub(crate) const DEFAULT_DSN: &str = "mongodb://root:pass@localhost:27017";
pub(crate) const DEFAULT_DB: &str = "haya";
pub(crate) const DEFAULT_COLLECTION: &str = "haya";
