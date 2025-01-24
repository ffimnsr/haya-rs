-- # Put the your SQL below migration seperator.
-- !UP

do $$
begin
create role e_auth noinherit createrole noreplication login password 'mysecretpassword';
exception when duplicate_object then raise notice '%, skipping', sqlerrm using errcode = sqlstate;
end
$$;

create schema if not exists auth authorization e_auth;
alter user e_auth set search_path = auth;

set role e_auth;

create table if not exists auth.users (
	instance_id uuid null,
	id uuid not null unique,
	aud varchar(255) null,
	"role" varchar(255) null,
	encrypted_password varchar(255) null,
	invited_at timestamptz null,
	confirmation_token varchar(255) null,
	confirmation_sent_at timestamptz null,
	recovery_token varchar(255) null,
	recovery_sent_at timestamptz null,
	email varchar(255) null unique,
	email_confirmed_at timestamptz null,
	email_change_token_new varchar(255) null,
	email_change varchar(255) null,
	email_change_sent_at timestamptz null,
    email_change_token_current varchar(255) null default '',
    email_change_confirm_status smallint default 0 check (email_change_confirm_status >= 0 and email_change_confirm_status <= 2),
    last_sign_in_at timestamptz null,
    raw_app_meta_data jsonb null,
    raw_user_meta_data jsonb null,
    is_super_admin bool null,
    phone text null unique default null,
    phone_confirmed_at timestamptz null default null,
    phone_change text null default '',
    phone_change_token varchar(255) null default '',
    phone_change_sent_at timestamptz null default null,
    confirmed_at timestamptz generated always as (least (users.email_confirmed_at, users.phone_confirmed_at)) stored,
    banned_until timestamptz null,
    reauthentication_token varchar(255) null default '',
    reauthentication_sent_at timestamptz null default null,
    is_sso_user boolean not null default false,
    is_anonymous boolean not null default false,
    deleted_at timestamptz null,
	created_at timestamptz null,
	updated_at timestamptz null,
	constraint users_pkey primary key (id)
);
comment on table auth.users is 'auth: stores user login data within a secure schema.';
comment on column auth.users.is_sso_user is 'auth: set this column to true when the account comes from sso. these accounts can have duplicate emails.';


create index if not exists users_instance_id_email_idx on auth.users using btree (instance_id, lower(email));
create index if not exists users_instance_id_idx on auth.users using btree (instance_id);
create index if not exists users_is_anonymous_idx  on auth.users using btree (is_anonymous);
create unique index if not exists confirmation_token_idx on auth.users using btree (confirmation_token) where confirmation_token !~ '^[0-9 ]*$';
create unique index if not exists recovery_token_idx on auth.users using btree (recovery_token) where recovery_token !~ '^[0-9 ]*$';
create unique index if not exists email_change_token_current_idx on auth.users using btree (email_change_token_current) where email_change_token_current !~ '^[0-9 ]*$';
create unique index if not exists email_change_token_new_idx on auth.users using btree (email_change_token_new) where email_change_token_new !~ '^[0-9 ]*$';
create unique index if not exists reauthentication_token_idx on auth.users using btree (reauthentication_token) where reauthentication_token !~ '^[0-9 ]*$';
create unique index if not exists users_email_partial_key_idx on auth.users (email) where (is_sso_user = false);
comment on index auth.users_email_partial_key_idx is 'auth: a partial unique index that applies only when is_sso_user is false';

create type auth.factor_type as enum('totp', 'webauthn', 'phone');
create type auth.factor_status as enum('unverified', 'verified');
create type auth.aal_level as enum('aal1', 'aal2', 'aal3');
create type auth.code_challenge_method as enum('s256', 'plain');

-- auth.sessions definition

create table if not exists auth.sessions (
    id uuid not null,
    user_id uuid not null,
    factor_id uuid null,
    aal auth.aal_level null,
    not_after timestamptz,
    user_agent text,
    ip inet,
    tag text,
    refreshed_at timestamp without time zone,
    created_at timestamptz null,
    updated_at timestamptz null,
    constraint sessions_pkey primary key (id),
    constraint sessions_user_id_fkey foreign key (user_id) references auth.users(id) on delete cascade
);
comment on table auth.sessions is 'auth: stores session data associated to a user.';
comment on column auth.sessions.not_after is 'auth: not after is a nullable column that contains a timestamp after which the session should be regarded as expired.';

create index if not exists sessions_user_id_created_at_idx on auth.sessions (user_id, created_at);
create index if not exists sessions_user_id_idx on auth.sessions (user_id);
create index if not exists sessions_not_after_idx on auth.sessions (not_after desc);

-- auth.refresh_tokens definition
create table if not exists auth.refresh_tokens (
	instance_id uuid null,
	id bigserial not null,
	"token" varchar(255) unique null,
	user_id varchar(255) null,
	revoked bool null,
    parent varchar(255) null,
    session_id uuid null references auth.sessions(id) on delete cascade,
	created_at timestamptz null,
	updated_at timestamptz null,
	constraint refresh_tokens_pkey primary key (id)
);
comment on table auth.refresh_tokens is 'auth: store of tokens used to refresh jwt tokens once they expire.';

create index if not exists refresh_tokens_instance_id_idx on auth.refresh_tokens using btree (instance_id);
create index if not exists refresh_tokens_instance_id_user_id_idx on auth.refresh_tokens using btree (instance_id, user_id);
create index if not exists refresh_tokens_parent_idx on auth.refresh_tokens using btree (parent);
create index if not exists refresh_tokens_session_id_revoked_idx on auth.refresh_tokens (session_id, revoked);
create index if not exists refresh_tokens_updated_at_idx on auth.refresh_tokens (updated_at desc);

-- auth.instances definition

create table if not exists auth.instances (
	id uuid not null,
	uuid uuid null,
	raw_base_config text null,
	created_at timestamptz null,
	updated_at timestamptz null,
	constraint instances_pkey primary key (id)
);
comment on table auth.instances is 'auth: manages users across multiple sites.';

-- auth.audit_log_entries definition

create table if not exists auth.audit_log_entries (
	instance_id uuid null,
	id uuid not null,
	payload json null,
    ip_address varchar(64) not null default '',
	created_at timestamptz null,
	constraint audit_log_entries_pkey primary key (id)
);
comment on table auth.audit_log_entries is 'auth: audit trail for user actions.';

create index if not exists audit_logs_instance_id_idx on auth.audit_log_entries using btree (instance_id);

-- auth.schema_migrations definition

create table if not exists auth.schema_migrations (
	"version" varchar(255) not null,
	constraint schema_migrations_pkey primary key ("version")
);
comment on table auth.schema_migrations is 'auth: manages updates to the auth system.';

-- gets the user id from the request cookie
create or replace function auth.uid()
returns uuid
language sql stable
as $$
  select
  coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;

-- gets the user id from the request cookie
create or replace function auth.role()
returns text
language sql stable
as $$
  select
  coalesce(
    nullif(current_setting('request.jwt.claim.role', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role')
  )::text
$$;

create or replace function auth.email()
returns text
language sql stable
as $$
  select
  coalesce(
    nullif(current_setting('request.jwt.claim.email', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'email')
  )::text
$$;

create or replace function auth.jwt()
returns jsonb
language sql stable
as $$
  select
    coalesce(
      nullif(current_setting('request.jwt.claim', true), ''),
      nullif(current_setting('request.jwt.claims', true), '')
    )::jsonb
$$;

-- auth.identities definition

create table if not exists auth.identities (
  id uuid default gen_random_uuid() primary key,
  provider_id text not null,
  user_id uuid not null,
  identity_data jsonb not null,
  provider text not null,
  last_sign_in_at timestamptz null,
  email text generated always as (lower(identity_data->>'email')) stored,
  created_at timestamptz null,
  updated_at timestamptz null,
  constraint identities_user_id_fkey foreign key (user_id) references auth.users(id) on delete cascade,
  constraint identities_provider_id_provider_unique unique(provider_id, provider)
);
comment on table auth.identities is 'auth: stores identities associated to a user.';
comment on column auth.identities.email is 'auth: email is a generated column that references the optional email property in the identity_data';

create index if not exists identities_user_id_idx on auth.identities using btree (user_id);
create index if not exists identities_email_idx on auth.identities (email text_pattern_ops);
comment on index auth.identities_email_idx is 'auth: ensures indexed queries on the email column';

-- auth.mfa_factors definition

create table if not exists auth.mfa_factors(
  id uuid not null,
  user_id uuid not null,
  friendly_name text null,
  factor_type auth.factor_type not null,
  status auth.factor_status not null,
  phone text unique default null,
  secret text null,
  web_authn_credential jsonb null,
  web_authn_aaguid uuid null,
  web_authn_session_data jsonb null,
  last_challenged_at timestamptz unique default null,
  created_at timestamptz not null,
  updated_at timestamptz not null,
  constraint mfa_factors_pkey primary key(id),
  constraint mfa_factors_user_id_fkey foreign key (user_id) references auth.users(id) on delete cascade
);
comment on table auth.mfa_factors is 'auth: stores metadata about factors';
create unique index if not exists mfa_factors_user_friendly_name_unique_idx on auth.mfa_factors (friendly_name, user_id) where trim(friendly_name) <> '';
create unique index if not exists mfa_factors_unique_phone_factor_per_user_idx on auth.mfa_factors (user_id, phone);
create index if not exists mfa_factors_factor_id_created_at_idx on auth.mfa_factors (user_id, created_at);
create index if not exists mfa_factors_user_id_idx on auth.mfa_factors(user_id);

-- auth.mfa_challenges definition

create table if not exists auth.mfa_challenges(
  id uuid not null,
  factor_id uuid not null,
  created_at timestamptz not null,
  verified_at timestamptz  null,
  ip_address  inet not null,
  otp_code text null,
  constraint mfa_challenges_pkey primary key (id),
  constraint mfa_challenges_auth_factor_id_fkey foreign key (factor_id) references auth.mfa_factors(id) on delete cascade
);
comment on table auth.mfa_challenges is 'auth: stores metadata about challenge requests made';
create index if not exists mfa_challenge_created_at_idx on auth.mfa_challenges (created_at desc);

-- auth.mfa_amr_claims definition

create table if not exists auth.mfa_amr_claims(
  id uuid primary key,
  session_id uuid not null,
  created_at timestamptz not null,
  updated_at timestamptz not null,
  authentication_method text not null,
  constraint mfa_amr_claims_session_id_authentication_method_pkey unique(session_id, authentication_method),
  constraint mfa_amr_claims_session_id_fkey foreign key(session_id) references auth.sessions(id) on delete cascade
);
comment on table auth.mfa_amr_claims is 'auth: stores authenticator method reference claims for multi factor authentication';

-- auth.sso_providers definition

create table if not exists auth.sso_providers (
	id uuid not null,
	resource_id text null,
	created_at timestamptz null,
	updated_at timestamptz null,
	primary key (id),
	constraint "resource_id not empty" check (resource_id = null or char_length(resource_id) > 0)
);
comment on table auth.sso_providers is 'auth: manages sso identity provider information; see saml_providers for saml.';
comment on column auth.sso_providers.resource_id is 'auth: uniquely identifies a sso provider according to a user-chosen resource id (case insensitive), useful in infrastructure as code.';

create unique index if not exists sso_providers_resource_id_idx on auth.sso_providers (lower(resource_id));

-- auth.sso_domains definition

create table if not exists auth.sso_domains (
	id uuid not null,
	sso_provider_id uuid not null,
	domain text not null,
	created_at timestamptz null,
	updated_at timestamptz null,
	primary key (id),
	foreign key (sso_provider_id) references auth.sso_providers (id) on delete cascade,
	constraint "domain not empty" check (char_length(domain) > 0)
);
comment on table auth.sso_domains is 'auth: manages sso email address domain mapping to an sso identity provider.';

create index if not exists sso_domains_sso_provider_id_idx on auth.sso_domains (sso_provider_id);
create unique index if not exists sso_domains_domain_idx on auth.sso_domains (lower(domain));

-- auth.saml_providers definition

create table if not exists auth.saml_providers (
	id uuid not null,
	sso_provider_id uuid not null,
	entity_id text not null unique,
	metadata_xml text not null,
	metadata_url text null,
	attribute_mapping jsonb null,
    name_id_format text null,
	created_at timestamptz null,
	updated_at timestamptz null,
	primary key (id),
	foreign key (sso_provider_id) references auth.sso_providers (id) on delete cascade,
	constraint "metadata_xml not empty" check (char_length(metadata_xml) > 0),
	constraint "metadata_url not empty" check (metadata_url = null or char_length(metadata_url) > 0),
	constraint "entity_id not empty" check (char_length(entity_id) > 0)
);
comment on table auth.saml_providers is 'auth: manages saml identity provider connections.';

create index if not exists saml_providers_sso_provider_id_idx on auth.saml_providers (sso_provider_id);

-- auth.flow_state definition

create table if not exists auth.flow_state(
  id uuid primary key,
  user_id uuid null,
  auth_code text not null,
  code_challenge_method auth.code_challenge_method not null,
  code_challenge text not null,
  provider_type text not null,
  provider_access_token text null,
  provider_refresh_token text null,
  authentication_method text not null,
  created_at timestamptz null,
  updated_at timestamptz null
);
comment on table auth.flow_state is 'stores metadata for pkce logins';

create index if not exists flow_state_auth_code_idx on auth.flow_state(auth_code);
create index if not exists flow_state_user_id_auth_method_idx on auth.flow_state (user_id, authentication_method);
create index if not exists flow_state_created_at_idx on auth.flow_state (created_at desc);

-- auth.saml_relay_states definition

create table if not exists auth.saml_relay_states (
	id uuid not null,
	sso_provider_id uuid not null,
	request_id text not null,
	for_email text null,
	redirect_to text null,
    flow_state_id uuid references auth.flow_state(id) on delete cascade default null,
    auth_code_issued_at timestamptz null,
	created_at timestamptz null,
	updated_at timestamptz null,
	primary key (id),
	foreign key (sso_provider_id) references auth.sso_providers (id) on delete cascade,
	constraint "request_id not empty" check(char_length(request_id) > 0)
);
comment on table auth.saml_relay_states is 'auth: contains saml relay state information for each service provider initiated login.';

create index if not exists saml_relay_states_sso_provider_id_idx on auth.saml_relay_states (sso_provider_id);
create index if not exists saml_relay_states_for_email_idx on auth.saml_relay_states (for_email);
create index if not exists saml_relay_states_created_at_idx on auth.saml_relay_states (created_at desc);

-- auth.one_time_token_type definition

create type auth.one_time_token_type as enum (
  'confirmation_token',
  'reauthentication_token',
  'recovery_token',
  'email_change_token_new',
  'email_change_token_current',
  'phone_change_token'
);

-- auth.one_time_tokens definition

create table if not exists auth.one_time_tokens (
  id uuid primary key,
  user_id uuid not null references auth.users on delete cascade,
  token_type auth.one_time_token_type not null,
  token_hash text not null,
  relates_to text not null,
  created_at timestamp without time zone not null default now(),
  updated_at timestamp without time zone not null default now(),
  check (char_length(token_hash) > 0)
);

create index if not exists one_time_tokens_token_hash_hash_idx on auth.one_time_tokens using hash (token_hash);
create index if not exists one_time_tokens_relates_to_hash_idx on auth.one_time_tokens using hash (relates_to);
create unique index if not exists one_time_tokens_user_id_token_type_key on auth.one_time_tokens (user_id, token_type);

alter table auth.schema_migrations enable row level security;
alter table auth.instances enable row level security;
alter table auth.users enable row level security;
alter table auth.audit_log_entries enable row level security;
alter table auth.saml_relay_states enable row level security;
alter table auth.refresh_tokens enable row level security;
alter table auth.mfa_factors enable row level security;
alter table auth.sessions enable row level security;
alter table auth.sso_providers enable row level security;
alter table auth.sso_domains enable row level security;
alter table auth.mfa_challenges enable row level security;
alter table auth.mfa_amr_claims enable row level security;
alter table auth.saml_providers enable row level security;
alter table auth.flow_state enable row level security;
alter table auth.identities enable row level security;
alter table auth.one_time_tokens enable row level security;

-- allow postgres role to select from auth tables and allow it to grant select to other roles
grant select on auth.schema_migrations to postgres with grant option;
grant select on auth.instances to postgres with grant option;
grant select on auth.users to postgres with grant option;
grant select on auth.audit_log_entries to postgres with grant option;
grant select on auth.saml_relay_states to postgres with grant option;
grant select on auth.refresh_tokens to postgres with grant option;
grant select on auth.mfa_factors to postgres with grant option;
grant select on auth.sessions to postgres with grant option;
grant select on auth.sso_providers to postgres with grant option;
grant select on auth.sso_domains to postgres with grant option;
grant select on auth.mfa_challenges to postgres with grant option;
grant select on auth.mfa_amr_claims to postgres with grant option;
grant select on auth.saml_providers to postgres with grant option;
grant select on auth.flow_state to postgres with grant option;
grant select on auth.identities to postgres with grant option;
grant select on auth.one_time_tokens to postgres with grant option;

reset role;

-- !DOWN

drop schema if exists auth cascade;
