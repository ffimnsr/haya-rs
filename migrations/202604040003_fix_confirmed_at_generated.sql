-- !UP

alter table auth.users
  drop column if exists confirmed_at;

alter table auth.users
  add column confirmed_at timestamptz generated always as (
    coalesce(
      least(users.email_confirmed_at, users.phone_confirmed_at),
      users.email_confirmed_at,
      users.phone_confirmed_at
    )
  ) stored;

-- !DOWN

alter table auth.users
  drop column if exists confirmed_at;

alter table auth.users
  add column confirmed_at timestamptz generated always as (
    least(users.email_confirmed_at, users.phone_confirmed_at)
  ) stored;
