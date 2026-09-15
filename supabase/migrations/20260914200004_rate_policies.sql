create table if not exists rate_policies (
  id text primary key check (id = 'active'),
  version text not null,
  policy jsonb not null,
  updated_at timestamptz not null default now()
);

insert into schema_migrations (version) values (5) on conflict (version) do nothing;
