-- !UP

alter table auth.flow_state
  add column if not exists factor_id uuid null,
  add column if not exists attempts integer not null default 0;

create index if not exists flow_state_factor_id_idx on auth.flow_state (factor_id);

-- !DOWN

drop index if exists auth.flow_state_factor_id_idx;

alter table auth.flow_state
  drop column if exists attempts,
  drop column if exists factor_id;
