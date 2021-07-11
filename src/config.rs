use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Config {
    pub log: LogOptions,
    pub serve: ServeOptions,
    pub dsn: String,
    pub webfinger: WebFingerOptions,
    pub oidc: OidcOptions,
    pub urls: UrlsOptions,
    pub ttl: TtlOptions,
    pub oauth2: Oauth2Options,
    pub secrets: SecretsOptions,
}

impl Config {
    /// Get the issuer url.
    pub(crate) fn get_issuer_url(&self) -> &String {
        &self.urls.self_ref.issuer.to_string()
    }

    /// Get the public url.
    pub(crate) fn get_public_url(&self) -> &String {
        &self.urls.self_ref.public.to_string()
    }

    /// Get the authorize url.
    pub(crate) fn get_authorization_url(&self) -> &String {
        let auth_url = &self.urls.self_ref.public.join("/authorize")
            .expect("Unable to join paths for authorize url");
        &auth_url.to_string()
    }

    /// Get the device authorize url.
    pub(crate) fn get_device_authorization_url(&self) -> &String {
        let auth_url = &self.urls.self_ref.public.join("/authorize/device")
            .expect("Unable to join paths for authorize url");
        &auth_url.to_string()
    }

    /// Get the token url.
    pub(crate) fn get_token_url(&self) -> &String {
        let auth_url = &self.urls.self_ref.public.join("/token")
            .expect("Unable to join paths for token url");
        &token_url.to_string()
    }

    /// Get the introspection url.
    pub(crate) fn get_introspection_url(&self) -> &String {
        let introspection_url = &self.urls.self_ref.public.join("/introspection")
            .expect("Unable to join paths for introspection url");
        &introspection_url.to_string()
    }

    /// Get the userinfo url.
    pub(crate) fn get_userinfo_url(&self) -> &String {
        let userinfo_url = &self.urls.self_ref.public.join("/userinfo")
            .expect("Unable to join paths for userinfo url");
        &userinfo_url.to_string()
    }

    /// Get the logout url.
    pub(crate) fn get_logout_url(&self) -> &String {
        &self.urls.self_ref.public.to_string()
    }

    /// Get the client registration url.
    pub(crate) fn get_client_registration_url(&self) -> &String {
        &self.urls.self_ref.public.to_string()
    }

    /// Get the backchannel authentications url.
    pub(crate) fn get_backchannel_authentication_url(&self) -> &String {
        &self.urls.self_ref.public.to_string()
    }

    /// Get the jwks certs url.
    pub(crate) fn get_jwks_certs_url(&self) -> &String {
        &self.urls.self_ref.public.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct LogOptions {
    pub level: String,
    pub format: String,
    pub show_sensitive_values: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct ServeOptions {
    pub public: PublicOptions,
    pub admin: AdminOptions,
    pub tls: TlsOptions,
    pub cookies: CookiesOptions,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct PublicOptions {
    pub port: i64,
    pub host: String,
    pub cors: CorsOptions,
    pub access_log: AccessLogOptions,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct CorsOptions {
    pub enabled: bool,
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub exposed_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age: i64,
    pub debug: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct AccessLogOptions {
    pub disable_for_health: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct AdminOptions {
    pub port: i64,
    pub host: String,
    pub cors: CorsOptions,
    pub access_log: AccessLogOptions,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct TlsOptions {
    pub key: KeyOptions,
    pub cert: CertOptions,
    pub allow_termination_from: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct KeyOptions {
    pub base64: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct CertOptions {
    pub base64: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct CookiesOptions {
    pub same_site_mode: String,
    pub same_site_legacy_workaround: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct WebFingerOptions {
    pub jwks: JwksOptions,
    pub oidc_discovery: OidcDiscoveryOptions,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct JwksOptions {
    pub broadcast_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct OidcDiscoveryOptions {
    pub client_registration_url: String,
    pub supported_claims: Vec<String>,
    pub supported_scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct OidcOptions {
    pub subject_identifiers: SubjectIdentifiersOptions,
    pub dynamic_client_registration: DynamicClientRegistrationOptions,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct SubjectIdentifiersOptions {
    pub supported_types: Vec<String>,
    pub pairwise: PairwiseOptions,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct PairwiseOptions {
    pub salt: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct DynamicClientRegistrationOptions {
    pub default_scope: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct UrlsOptions {
    #[serde(rename = "self")]
    pub self_ref: SelfOptions,
    pub login: Url,
    pub consent: Url,
    pub logout: Url,
    pub error: Url,
    pub post_logout_redirect: Url,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct SelfOptions {
    pub issuer: Url,
    pub public: Url,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct TtlOptions {
    pub login_consent_request: String,
    pub access_token: String,
    pub refresh_token: String,
    pub id_token: String,
    pub auth_code: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Oauth2Options {
    pub expose_internal_errors: bool,
    pub include_legacy_error_fields: bool,
    pub hashers: HashersOptions,
    pub pkce: PkceOptions,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct HashersOptions {
    pub bcrypt: BcryptOptions,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct BcryptOptions {
    pub cost: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct PkceOptions {
    pub enforced: bool,
    pub enforced_for_public_clients: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct SecretsOptions {
    pub system: Vec<String>,
    pub cookie: Vec<String>,
}
