alter table users add column if not exists password_hash text;
alter table auth_challenges add column if not exists provider text;

create table if not exists auth_identities (
  provider text not null,
  subject text not null,
  user_id text not null references users(id),
  created_at timestamptz not null default now(),
  primary key (provider, subject)
);

create index if not exists auth_identities_user_idx on auth_identities(user_id);
create unique index if not exists auth_identities_user_provider_idx on auth_identities(user_id, provider);
insert into schema_migrations (version) values (6) on conflict (version) do nothing;
