create table if not exists auth.oidc_providers (
  id uuid primary key,
  name text not null,
  issuer text not null,
  client_id text not null,
  client_secret text not null,
  redirect_uri text not null,
  scopes jsonb not null default '["openid","email","profile"]'::jsonb,
  pkce boolean not null default true,
  allowed_email_domains jsonb not null default '[]'::jsonb,
  created_at timestamptz null,
  updated_at timestamptz null,
  constraint "oidc_provider_name_not_empty" check (char_length(trim(name)) > 0),
  constraint "oidc_provider_issuer_not_empty" check (char_length(trim(issuer)) > 0),
  constraint "oidc_provider_client_id_not_empty" check (char_length(trim(client_id)) > 0),
  constraint "oidc_provider_client_secret_not_empty" check (char_length(trim(client_secret)) > 0),
  constraint "oidc_provider_redirect_uri_not_empty" check (char_length(trim(redirect_uri)) > 0)
);

comment on table auth.oidc_providers is 'auth: manages OIDC identity provider connections for the Rust runtime.';
create unique index if not exists oidc_providers_name_idx on auth.oidc_providers (lower(name));

alter table auth.oidc_providers enable row level security;
grant select on auth.oidc_providers to postgres with grant option;
