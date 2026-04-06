create table if not exists auth.rate_limits(
  key text primary key,
  attempts integer not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists rate_limits_expires_at_idx on auth.rate_limits (expires_at);
