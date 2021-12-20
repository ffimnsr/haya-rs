-- # Put the your SQL below migration seperator.
-- !UP
CREATE TABLE IF NOT EXISTS public.hydra_client
(
    pk SERIAL PRIMARY KEY,
    id VARCHAR(255) NOT NULL,
    client_name TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    grant_types TEXT NOT NULL,
    response_types TEXT NOT NULL,
    scope TEXT NOT NULL,
    owner TEXT NOT NULL,
    policy_uri TEXT NOT NULL,
    tos_uri TEXT NOT NULL,
    client_uri TEXT NOT NULL,
    logo_uri TEXT NOT NULL,
    contacts TEXT NOT NULL,
    client_secret_expires_at INTEGER NOT NULL DEFAULT 0,
    sector_identifier_uri TEXT NOT NULL,
    jwks TEXT NOT NULL,
    jwks_uri TEXT NOT NULL,
    request_uris TEXT NOT NULL,
    token_endpoint_auth_method VARCHAR(25) NOT NULL DEFAULT '',
    request_object_signing_alg VARCHAR(10) NOT NULL DEFAULT '',
    userinfo_signed_response_alg VARCHAR(10) NOT NULL DEFAULT '',
    subject_type VARCHAR(15) NOT NULL DEFAULT '',
    allowed_cors_origins TEXT NOT NULL,
    audience TEXT NOT NULL,
    frontchannel_logout_uri TEXT NOT NULL DEFAULT '',
    frontchannel_logout_session_required boolean NOT NULL DEFAULT false,
    post_logout_redirect_uris TEXT NOT NULL DEFAULT '',
    backchannel_logout_uri TEXT NOT NULL DEFAULT '',
    backchannel_logout_session_required boolean NOT NULL DEFAULT false,
    metadata TEXT NOT NULL,
    token_endpoint_auth_signing_alg VARCHAR(10) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- !DOWN
