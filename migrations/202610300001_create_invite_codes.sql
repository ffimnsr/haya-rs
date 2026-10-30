-- One-time invite codes for public signup. Only the SHA-256 hash of a code is
-- stored; the plaintext value is returned once when an admin creates it.
create table if not exists auth.invite_codes (
  id uuid primary key,
  code_hash text not null unique,
  label text null,
  note text null,
  created_by uuid null references auth.users(id) on delete set null,
  expires_at timestamptz null,
  used_at timestamptz null,
  used_by uuid null references auth.users(id) on delete set null,
  revoked_at timestamptz null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists invite_codes_active_idx
  on auth.invite_codes (created_at desc)
  where used_at is null and revoked_at is null;
