-- Short-lived OAuth and magic-link challenges. Only SHA-256 token hashes are stored.
create table if not exists auth_challenges (
  token_hash text primary key,
  kind text not null check (kind in ('oauth_state', 'magic_link')),
  user_id text,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists auth_challenges_expiry_idx on auth_challenges(expires_at);
insert into schema_migrations (version) values (3) on conflict (version) do nothing;
