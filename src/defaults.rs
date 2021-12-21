#![allow(dead_code)]
pub(crate) const AUTHORIZATION_CODE_LIFETIME: i64 = 300;
pub(crate) const ACCESS_TOKEN_LIFETIME: i64 = 3600;
pub(crate) const REFRESH_TOKEN_LIFETIME: i64 = 1_209_600;

lazy_static::lazy_static! {
    pub static ref SHARED_ENCODING_KEY: Result<jsonwebtoken::EncodingKey, jsonwebtoken::errors::Error> = {
        jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!("../certs/priv-key.pem"))
    };

    pub static ref SHARED_DECODING_KEY: Result<jsonwebtoken::DecodingKey<'static>, jsonwebtoken::errors::Error> = {
        jsonwebtoken::DecodingKey::from_rsa_pem(include_bytes!("../certs/pub.pem"))
    };
}
