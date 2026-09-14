-- Server-owned data only. PDF bytes, paper metadata, annotations and
-- translation text remain in the browser's local database.

create table if not exists schema_migrations (
  version integer primary key,
  applied_at timestamptz not null default now()
);

insert into schema_migrations (version) values (1) on conflict (version) do nothing;

create table if not exists users (
  id text primary key,
  email_hash text not null unique,
  created_at timestamptz not null default now(),
  status text not null default 'active' check (status in ('active', 'disabled', 'deleted'))
);

create table if not exists subscriptions (
  id text primary key,
  user_id text not null references users(id),
  provider text not null,
  provider_customer_id text,
  provider_subscription_id text,
  plan_id text not null,
  status text not null,
  current_period_start timestamptz not null,
  current_period_end timestamptz not null,
  grace_until timestamptz,
  cancel_at_period_end boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists subscriptions_user_id_idx on subscriptions(user_id);

create table if not exists credit_ledger (
  id text primary key,
  user_id text not null references users(id),
  request_id text,
  type text not null check (type in ('grant', 'reserve', 'consume', 'release', 'refund', 'expire')),
  amount bigint not null check (amount > 0),
  plan_id text not null,
  rate_version text not null,
  source_id text,
  original_id text,
  created_at timestamptz not null default now()
);

create index if not exists credit_ledger_user_created_idx on credit_ledger(user_id, created_at);
create index if not exists credit_ledger_request_idx on credit_ledger(request_id);
create unique index if not exists credit_ledger_grant_source_idx on credit_ledger(user_id, source_id) where type = 'grant' and source_id is not null;

create table if not exists translation_requests (
  id text primary key,
  user_id text not null references users(id),
  idempotency_key text not null,
  request_hash text not null,
  mode text not null,
  model text not null,
  source_language text not null,
  target_language text not null,
  segment_count integer not null,
  input_tokens bigint,
  output_tokens bigint,
  credits_reserved bigint not null default 0,
  credits_consumed bigint not null default 0,
  status text not null,
  error_code text,
  created_at timestamptz not null default now(),
  completed_at timestamptz,
  unique(user_id, idempotency_key)
);

create index if not exists translation_requests_user_created_idx on translation_requests(user_id, created_at);

create table if not exists webhook_events (
  id text primary key,
  provider text not null,
  event_id text not null,
  event_type text not null,
  processed_at timestamptz,
  created_at timestamptz not null default now(),
  unique(provider, event_id)
);

create table if not exists revoked_sessions (
  session_hash text primary key,
  expires_at timestamptz not null
);
