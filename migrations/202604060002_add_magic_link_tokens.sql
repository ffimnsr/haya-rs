alter table auth.users
  add column if not exists magic_link_token varchar(255) null,
  add column if not exists magic_link_sent_at timestamptz null;

create unique index if not exists magic_link_token_idx
  on auth.users using btree (magic_link_token)
  where magic_link_token !~ '^[0-9 ]*$';
