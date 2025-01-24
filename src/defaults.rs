#![allow(dead_code)]
pub const AUTHORIZATION_CODE_LIFETIME: i64 = 300;
pub const ACCESS_TOKEN_LIFETIME: i64 = 3600;
pub const REFRESH_TOKEN_LIFETIME: i64 = 1_209_600;
pub const DEFAULT_DATABASE_URL: &str = "postgres://postgres:mysecretpassword@localhost:5432";
pub const DEFAULT_DB_NAME: &str = "haya";
pub const DEFAULT_COLLECTION: &str = "haya";
pub const DEFAULT_PORT: u16 = 8080;
