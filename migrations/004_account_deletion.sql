-- Account deletion is delayed so a user can cancel an accidental request.
alter table users add column if not exists deletion_requested_at timestamptz;
alter table users add column if not exists deletion_execute_at timestamptz;
create index if not exists users_deletion_execute_idx on users(deletion_execute_at) where deletion_execute_at is not null;
insert into schema_migrations (version) values (4) on conflict (version) do nothing;
