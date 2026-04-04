-- !UP

alter table auth.flow_state
  add column if not exists nonce text null,
  add column if not exists redirect_to text null,
  add column if not exists pkce_verifier text null,
  add column if not exists expires_at timestamptz null;

alter table auth.users
  drop constraint if exists users_email_key;

-- !DOWN

alter table auth.flow_state
  drop column if exists expires_at,
  drop column if exists pkce_verifier,
  drop column if exists redirect_to,
  drop column if exists nonce;

alter table auth.users
  add constraint users_email_key unique (email);
