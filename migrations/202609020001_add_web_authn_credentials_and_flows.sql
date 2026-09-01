alter table auth.mfa_factors
  add column if not exists web_authn_credential_id bytea null;

alter table auth.mfa_factors
  add constraint mfa_factors_web_authn_credential_required_check
    check (
      factor_type <> 'webauthn'::auth.factor_type
      or (web_authn_credential_id is not null and web_authn_credential is not null)
    ),
  add constraint mfa_factors_non_web_authn_credential_id_check
    check (
      factor_type = 'webauthn'::auth.factor_type
      or web_authn_credential_id is null
    );

create unique index mfa_factors_web_authn_credential_id_unique_idx
  on auth.mfa_factors (web_authn_credential_id)
  where factor_type = 'webauthn'::auth.factor_type;

create table auth.web_authn_flows (
  id uuid primary key,
  user_id uuid null,
  purpose text not null,
  challenge bytea not null,
  state jsonb not null,
  friendly_name text null,
  attempts integer not null default 0,
  expires_at timestamptz not null,
  consumed_at timestamptz null,
  created_at timestamptz not null,
  updated_at timestamptz not null,
  constraint web_authn_flows_user_id_fkey
    foreign key (user_id) references auth.users(id) on delete cascade,
  constraint web_authn_flows_purpose_check
    check (purpose in ('registration', 'authentication')),
  constraint web_authn_flows_registration_user_check
    check (purpose <> 'registration' or user_id is not null),
  constraint web_authn_flows_challenge_length_check
    check (octet_length(challenge) = 32),
  constraint web_authn_flows_attempts_check
    check (attempts >= 0)
);

create index web_authn_flows_expires_at_idx
  on auth.web_authn_flows (expires_at);
create index web_authn_flows_user_id_idx
  on auth.web_authn_flows (user_id)
  where user_id is not null;
create index web_authn_flows_active_lookup_idx
  on auth.web_authn_flows (purpose, user_id, created_at desc)
  where consumed_at is null;

-- !DOWN

drop index if exists auth.web_authn_flows_active_lookup_idx;
drop index if exists auth.web_authn_flows_user_id_idx;
drop index if exists auth.web_authn_flows_expires_at_idx;
drop table if exists auth.web_authn_flows;
drop index if exists auth.mfa_factors_web_authn_credential_id_unique_idx;
alter table auth.mfa_factors
  drop constraint if exists mfa_factors_non_web_authn_credential_id_check,
  drop constraint if exists mfa_factors_web_authn_credential_required_check,
  drop column if exists web_authn_credential_id;
