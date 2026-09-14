-- Additive billing fields. Existing subscriptions remain valid during rollout.
alter table subscriptions add column if not exists grace_until timestamptz;
alter table subscriptions add column if not exists cancel_at_period_end boolean not null default false;
alter table subscriptions add column if not exists last_event_at timestamptz;
alter table subscriptions add column if not exists last_event_id text;
alter table subscriptions add column if not exists pending_plan_id text;
alter table subscriptions add column if not exists pending_plan_at timestamptz;
alter table webhook_events add column if not exists processing_at timestamptz;
create unique index if not exists subscriptions_provider_subscription_idx on subscriptions(provider, provider_subscription_id) where provider_subscription_id is not null;
insert into schema_migrations (version) values (2) on conflict (version) do nothing;
