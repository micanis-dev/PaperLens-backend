package persistence

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/micanis/paperlens/backend/internal/account"
	"github.com/micanis/paperlens/backend/internal/billing"
	"github.com/micanis/paperlens/backend/internal/contract"
	"github.com/micanis/paperlens/backend/internal/credits"
	"github.com/micanis/paperlens/backend/internal/translation"
)

// Open validates the connection before the API starts accepting requests.
func Open(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxIdleTime(5 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// Migrate applies only additive, idempotent initial DDL. Destructive changes
// remain explicit versioned migrations in migrations/.
func Migrate(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, schemaSQL)
	return err
}

// PostgresRatePolicyStore keeps the currently published conversion policy in
// one row. Completed requests retain their own rate version; this table is
// only the source for future estimates and reservations.
type PostgresRatePolicyStore struct{ db *sql.DB }

func NewPostgresRatePolicyStore(db *sql.DB) *PostgresRatePolicyStore {
	return &PostgresRatePolicyStore{db: db}
}

func (s *PostgresRatePolicyStore) Get(ctx context.Context) (credits.RatePolicy, error) {
	var raw []byte
	if err := s.db.QueryRowContext(ctx, `select policy from rate_policies where id='active'`).Scan(&raw); err != nil {
		return credits.RatePolicy{}, err
	}
	var policy credits.RatePolicy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return credits.RatePolicy{}, err
	}
	if err := policy.Validate(); err != nil {
		return credits.RatePolicy{}, err
	}
	return policy, nil
}

func (s *PostgresRatePolicyStore) Save(ctx context.Context, policy credits.RatePolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `insert into rate_policies (id,version,policy,updated_at) values ('active',$1,$2,now()) on conflict (id) do update set version=excluded.version,policy=excluded.policy,updated_at=now()`, policy.Version, raw)
	return err
}

const schemaSQL = `
create table if not exists schema_migrations (version integer primary key, applied_at timestamptz not null default now());
create table if not exists users (id text primary key, email_hash text not null unique, created_at timestamptz not null default now(), status text not null default 'active', deletion_requested_at timestamptz, deletion_execute_at timestamptz);
alter table users add column if not exists deletion_requested_at timestamptz;
alter table users add column if not exists deletion_execute_at timestamptz;
create index if not exists users_deletion_execute_idx on users(deletion_execute_at) where deletion_execute_at is not null;
create table if not exists subscriptions (id text primary key, user_id text not null references users(id), provider text not null, provider_customer_id text, provider_subscription_id text, plan_id text not null, status text not null, current_period_start timestamptz not null, current_period_end timestamptz not null, grace_until timestamptz, cancel_at_period_end boolean not null default false, last_event_at timestamptz, last_event_id text, pending_plan_id text, pending_plan_at timestamptz, created_at timestamptz not null default now(), updated_at timestamptz not null default now());
alter table subscriptions add column if not exists grace_until timestamptz;
alter table subscriptions add column if not exists cancel_at_period_end boolean not null default false;
alter table subscriptions add column if not exists last_event_at timestamptz;
alter table subscriptions add column if not exists last_event_id text;
alter table subscriptions add column if not exists pending_plan_id text;
alter table subscriptions add column if not exists pending_plan_at timestamptz;
create index if not exists subscriptions_user_id_idx on subscriptions(user_id);
create unique index if not exists subscriptions_provider_subscription_idx on subscriptions(provider, provider_subscription_id) where provider_subscription_id is not null;
create table if not exists credit_ledger (id text primary key, user_id text not null references users(id), request_id text, type text not null, amount bigint not null check (amount > 0), plan_id text not null, rate_version text not null, source_id text, original_id text, created_at timestamptz not null default now());
create index if not exists credit_ledger_user_created_idx on credit_ledger(user_id, created_at);
create index if not exists credit_ledger_request_idx on credit_ledger(request_id);
create unique index if not exists credit_ledger_grant_source_idx on credit_ledger(user_id, source_id) where type = 'grant' and source_id is not null;
create table if not exists translation_requests (id text primary key, user_id text not null references users(id), idempotency_key text not null, request_hash text not null, mode text not null, model text not null, rate_version text not null default '2026-09-01', source_language text not null, target_language text not null, segment_count integer not null, input_tokens bigint, output_tokens bigint, credits_reserved bigint not null default 0, credits_consumed bigint not null default 0, status text not null, error_code text, created_at timestamptz not null default now(), completed_at timestamptz, unique(user_id, idempotency_key));
alter table translation_requests add column if not exists rate_version text not null default '2026-09-01';
create index if not exists translation_requests_user_created_idx on translation_requests(user_id, created_at);
create table if not exists webhook_events (id text primary key, provider text not null, event_id text not null, event_type text not null, processing_at timestamptz, processed_at timestamptz, created_at timestamptz not null default now(), unique(provider, event_id));
alter table webhook_events add column if not exists processing_at timestamptz;
create table if not exists revoked_sessions (session_hash text primary key, expires_at timestamptz not null);
create table if not exists auth_challenges (token_hash text primary key, kind text not null check (kind in ('oauth_state','magic_link')), user_id text, expires_at timestamptz not null, created_at timestamptz not null default now());
create index if not exists auth_challenges_expiry_idx on auth_challenges(expires_at);
create table if not exists rate_policies (id text primary key check (id='active'), version text not null, policy jsonb not null, updated_at timestamptz not null default now());
insert into schema_migrations (version) values (1), (2), (3), (4), (5) on conflict (version) do nothing;
`

// PostgresAccountStore implements the 24-hour deletion grace period. The
// transaction removes server-owned operational rows and anonymizes the user
// row, while preserving provider webhook IDs for audit/replay protection.
type PostgresAccountStore struct{ db *sql.DB }

func NewPostgresAccountStore(db *sql.DB) *PostgresAccountStore { return &PostgresAccountStore{db: db} }

func (s *PostgresAccountStore) RequestDeletion(ctx context.Context, userID string, requestedAt, executeAt time.Time) (account.Deletion, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return account.Deletion{}, err
	}
	defer tx.Rollback()
	var status string
	var existingRequested, existingExecute sql.NullTime
	err = tx.QueryRowContext(ctx, `select status,deletion_requested_at,deletion_execute_at from users where id=$1 for update`, userID).Scan(&status, &existingRequested, &existingExecute)
	if errors.Is(err, sql.ErrNoRows) {
		return account.Deletion{}, account.ErrNotFound
	}
	if err != nil {
		return account.Deletion{}, err
	}
	if status != "active" {
		return account.Deletion{}, account.ErrAlreadyDeleted
	}
	if existingRequested.Valid && existingExecute.Valid {
		if err := tx.Commit(); err != nil {
			return account.Deletion{}, err
		}
		return account.Deletion{RequestedAt: existingRequested.Time, ExecuteAt: existingExecute.Time}, nil
	}
	if _, err := tx.ExecContext(ctx, `update users set deletion_requested_at=$2,deletion_execute_at=$3 where id=$1`, userID, requestedAt, executeAt); err != nil {
		return account.Deletion{}, err
	}
	if err := tx.Commit(); err != nil {
		return account.Deletion{}, err
	}
	return account.Deletion{RequestedAt: requestedAt, ExecuteAt: executeAt}, nil
}

func (s *PostgresAccountStore) CancelDeletion(ctx context.Context, userID string) error {
	result, err := s.db.ExecContext(ctx, `update users set deletion_requested_at=null,deletion_execute_at=null where id=$1 and status='active'`, userID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		active, activeErr := s.IsActive(ctx, userID)
		if activeErr != nil {
			return activeErr
		}
		if !active {
			return account.ErrAlreadyDeleted
		}
		return account.ErrNotFound
	}
	return nil
}

func (s *PostgresAccountStore) Deletion(ctx context.Context, userID string) (*account.Deletion, error) {
	var requested, execute sql.NullTime
	err := s.db.QueryRowContext(ctx, `select deletion_requested_at,deletion_execute_at from users where id=$1 and status='active'`, userID).Scan(&requested, &execute)
	if errors.Is(err, sql.ErrNoRows) {
		active, activeErr := s.IsActive(ctx, userID)
		if activeErr != nil {
			return nil, activeErr
		}
		if !active {
			return nil, account.ErrAlreadyDeleted
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !requested.Valid || !execute.Valid {
		return nil, nil
	}
	return &account.Deletion{RequestedAt: requested.Time, ExecuteAt: execute.Time}, nil
}

func (s *PostgresAccountStore) ProcessDue(ctx context.Context, userID string, now time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var exists bool
	err = tx.QueryRowContext(ctx, `select true from users where id=$1 and status='active' and deletion_execute_at is not null and deletion_execute_at <= $2 for update`, userID, now).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, table := range []string{"subscriptions", "credit_ledger", "translation_requests", "auth_challenges"} {
		if _, err := tx.ExecContext(ctx, `delete from `+table+` where user_id=$1`, userID); err != nil {
			return false, err
		}
	}
	// Keep the stable account ID only as an inert tombstone. The old email hash
	// and all billable/request data are removed, and ensureUser never revives a
	// non-active row.
	if _, err := tx.ExecContext(ctx, `update users set status='deleted',email_hash=$2,deletion_requested_at=null,deletion_execute_at=null where id=$1`, userID, "deleted:"+userID); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return exists, nil
}

func (s *PostgresAccountStore) ProcessAllDue(ctx context.Context, now time.Time) (int, error) {
	rows, err := s.db.QueryContext(ctx, `select id from users where status='active' and deletion_execute_at is not null and deletion_execute_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var userIDs []string
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return 0, err
		}
		userIDs = append(userIDs, userID)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	count := 0
	for _, userID := range userIDs {
		deleted, err := s.ProcessDue(ctx, userID, now)
		if err != nil {
			return count, err
		}
		if deleted {
			count++
		}
	}
	return count, nil
}

func (s *PostgresAccountStore) IsActive(ctx context.Context, userID string) (bool, error) {
	var active bool
	err := s.db.QueryRowContext(ctx, `select status='active' from users where id=$1`, userID).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return active, err
}

// TranslationRepository stores request metadata durably. Result text is kept
// only in the process cache for the active request and is never written to
// PostgreSQL, matching the local-first/privacy boundary.
type TranslationRepository struct {
	db    *sql.DB
	mu    sync.RWMutex
	cache map[string]*contract.TranslationResource
}

func NewTranslationRepository(db *sql.DB) *TranslationRepository {
	return &TranslationRepository{db: db, cache: make(map[string]*contract.TranslationResource)}
}

func (r *TranslationRepository) Create(resource *contract.TranslationResource) error {
	if err := ensureUser(context.Background(), r.db, resource.UserID); err != nil {
		return err
	}
	_, err := r.db.Exec(`insert into translation_requests (id, user_id, idempotency_key, request_hash, mode, model, rate_version, source_language, target_language, segment_count, credits_reserved, status, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, resource.ID, resource.UserID, resource.IdempotencyKey, resource.RequestHash, resource.Mode, resource.Model, resource.RateVersion, resource.SourceLanguage, resource.TargetLanguage, resource.SegmentCount, resource.CreditsReserved, resource.Status, resource.CreatedAt)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.cache[resource.ID] = cloneResourceMetadata(resource)
	r.mu.Unlock()
	return nil
}

func (r *TranslationRepository) Get(userID, id string) (*contract.TranslationResource, error) {
	r.mu.RLock()
	cached := r.cache[id]
	r.mu.RUnlock()
	if cached != nil && cached.UserID == userID {
		return cloneResource(cached), nil
	}
	return r.query(userID, `id = $2`, id)
}

func (r *TranslationRepository) FindByIdempotency(userID, key string) (*contract.TranslationResource, error) {
	return r.query(userID, `idempotency_key = $2`, key)
}

func (r *TranslationRepository) ListRunningBefore(ctx context.Context, before time.Time) ([]*contract.TranslationResource, error) {
	rows, err := r.db.QueryContext(ctx, `select id,user_id,idempotency_key,request_hash,mode,model,rate_version,source_language,target_language,segment_count,credits_reserved,credits_consumed,status,error_code,created_at,completed_at from translation_requests where status in ('running','pending') and created_at < $1 order by created_at,id`, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	resources := make([]*contract.TranslationResource, 0)
	for rows.Next() {
		resource, scanErr := scanResource(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		r.mu.RLock()
		if cached := r.cache[resource.ID]; cached != nil {
			resource = cloneResource(cached)
		}
		r.mu.RUnlock()
		resources = append(resources, resource)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return resources, nil
}

func (r *TranslationRepository) Update(resource *contract.TranslationResource) error {
	completed := any(nil)
	if resource.CompletedAt != nil {
		completed = *resource.CompletedAt
	}
	_, err := r.db.Exec(`update translation_requests set status=$1, error_code=$2, input_tokens=$3, output_tokens=$4, credits_consumed=$5, completed_at=$6 where id=$7 and user_id=$8`, resource.Status, nullableString(string(resource.ErrorCode)), resultInputTokens(resource), resultOutputTokens(resource), resource.CreditsConsumed, completed, resource.ID, resource.UserID)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.cache[resource.ID] = cloneResourceMetadata(resource)
	r.mu.Unlock()
	return nil
}

func (r *TranslationRepository) query(userID, predicate, value string) (*contract.TranslationResource, error) {
	row := r.db.QueryRow(`select id,user_id,idempotency_key,request_hash,mode,model,rate_version,source_language,target_language,segment_count,credits_reserved,credits_consumed,status,error_code,created_at,completed_at from translation_requests where user_id=$1 and `+predicate, userID, value)
	resource, err := scanResource(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, translation.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.mu.RLock()
	if cached := r.cache[resource.ID]; cached != nil {
		resource = cloneResource(cached)
	}
	r.mu.RUnlock()
	return resource, nil
}

type rowScanner interface{ Scan(...any) error }

func scanResource(row rowScanner) (*contract.TranslationResource, error) {
	var resource contract.TranslationResource
	var mode, status string
	var rateVersion string
	var errorCode sql.NullString
	var completed sql.NullTime
	if err := row.Scan(&resource.ID, &resource.UserID, &resource.IdempotencyKey, &resource.RequestHash, &mode, &resource.Model, &rateVersion, &resource.SourceLanguage, &resource.TargetLanguage, &resource.SegmentCount, &resource.CreditsReserved, &resource.CreditsConsumed, &status, &errorCode, &resource.CreatedAt, &completed); err != nil {
		return nil, err
	}
	resource.Mode = contract.TranslationMode(mode)
	resource.RateVersion = rateVersion
	resource.Status = contract.TranslationStatus(status)
	if errorCode.Valid {
		resource.ErrorCode = contract.APIErrorCode(errorCode.String)
	}
	if completed.Valid {
		value := completed.Time
		resource.CompletedAt = &value
	}
	return &resource, nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func nullableTimePtr(value *time.Time) any {
	if value == nil || value.IsZero() {
		return nil
	}
	return *value
}

func resultInputTokens(resource *contract.TranslationResource) any {
	if resource.Result == nil {
		return nil
	}
	return resource.Result.Usage.InputTokens
}

func resultOutputTokens(resource *contract.TranslationResource) any {
	if resource.Result == nil {
		return nil
	}
	return resource.Result.Usage.OutputTokens
}

func cloneResource(resource *contract.TranslationResource) *contract.TranslationResource {
	copy := *resource
	if resource.Result != nil {
		result := *resource.Result
		result.Segments = append([]contract.TranslatedSegment(nil), resource.Result.Segments...)
		result.Warnings = append([]string(nil), resource.Result.Warnings...)
		copy.Result = &result
	}
	return &copy
}

func cloneResourceMetadata(resource *contract.TranslationResource) *contract.TranslationResource {
	copy := cloneResource(resource)
	copy.Result = nil
	return copy
}

// PostgresRevocations makes logout survive process restarts and Fly machine
// replacement without storing the signed session cookie itself.
type PostgresRevocations struct{ db *sql.DB }

func NewPostgresRevocations(db *sql.DB) *PostgresRevocations { return &PostgresRevocations{db: db} }

func (s *PostgresRevocations) Revoke(value string, until time.Time) {
	if value == "" {
		return
	}
	_, _ = s.db.Exec(`insert into revoked_sessions (session_hash,expires_at) values ($1,$2) on conflict (session_hash) do update set expires_at=excluded.expires_at`, authRevocationKey(value), until)
}

func (s *PostgresRevocations) IsRevoked(value string, now time.Time) bool {
	var expires time.Time
	err := s.db.QueryRow(`select expires_at from revoked_sessions where session_hash=$1`, authRevocationKey(value)).Scan(&expires)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	if err != nil {
		// Fail closed when the revocation store cannot be read.
		return true
	}
	if !now.Before(expires) {
		_, _ = s.db.Exec(`delete from revoked_sessions where session_hash=$1`, authRevocationKey(value))
		return false
	}
	return true
}

func authRevocationKey(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

// PostgresLoginStore makes one-time login challenges survive API restarts and
// be shared by multiple Fly machines. The value stored is already a SHA-256
// hash, so a database read cannot be used to log in without the URL token.
type PostgresLoginStore struct{ db *sql.DB }

func NewPostgresLoginStore(db *sql.DB) *PostgresLoginStore { return &PostgresLoginStore{db: db} }

func (s *PostgresLoginStore) SaveOAuthState(hash string, expiresAt time.Time) error {
	_, err := s.db.Exec(`insert into auth_challenges (token_hash,kind,expires_at) values ($1,'oauth_state',$2) on conflict (token_hash) do update set kind=excluded.kind,expires_at=excluded.expires_at`, hash, expiresAt)
	return err
}

func (s *PostgresLoginStore) ConsumeOAuthState(hash string, now time.Time) (bool, error) {
	var consumed bool
	err := s.db.QueryRow(`delete from auth_challenges where token_hash=$1 and kind='oauth_state' and expires_at > $2 returning true`, hash, now).Scan(&consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return consumed, err
}

func (s *PostgresLoginStore) SaveMagicLink(hash, userID string, expiresAt time.Time) error {
	_, err := s.db.Exec(`insert into auth_challenges (token_hash,kind,user_id,expires_at) values ($1,'magic_link',$2,$3) on conflict (token_hash) do update set kind=excluded.kind,user_id=excluded.user_id,expires_at=excluded.expires_at`, hash, userID, expiresAt)
	return err
}

func (s *PostgresLoginStore) ConsumeMagicLink(hash string, now time.Time) (string, bool, error) {
	var userID string
	err := s.db.QueryRow(`delete from auth_challenges where token_hash=$1 and kind='magic_link' and expires_at > $2 returning user_id`, hash, now).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return userID, err == nil, err
}

// PostgresBillingStore persists only subscription identifiers and lifecycle
// state. Stripe payment details and customer data remain owned by Stripe.
type PostgresBillingStore struct{ db *sql.DB }

func NewPostgresBillingStore(db *sql.DB) *PostgresBillingStore {
	return &PostgresBillingStore{db: db}
}

const subscriptionSelect = `select id,user_id,provider,coalesce(provider_customer_id,''),coalesce(provider_subscription_id,''),plan_id,status,current_period_start,current_period_end,grace_until,cancel_at_period_end,coalesce(last_event_at,'epoch'::timestamptz),coalesce(last_event_id,''),coalesce(pending_plan_id,''),pending_plan_at,updated_at from subscriptions`

func (s *PostgresBillingStore) FindByUser(ctx context.Context, userID string) (billing.Subscription, error) {
	row := s.db.QueryRowContext(ctx, subscriptionSelect+` where user_id=$1 order by updated_at desc limit 1`, userID)
	return scanSubscription(row)
}

func (s *PostgresBillingStore) FindByProviderSubscription(ctx context.Context, subscriptionID string) (billing.Subscription, error) {
	row := s.db.QueryRowContext(ctx, subscriptionSelect+` where provider='stripe' and provider_subscription_id=$1 limit 1`, subscriptionID)
	return scanSubscription(row)
}

func (s *PostgresBillingStore) FindByProviderCustomer(ctx context.Context, customerID string) (billing.Subscription, error) {
	row := s.db.QueryRowContext(ctx, subscriptionSelect+` where provider='stripe' and provider_customer_id=$1 order by updated_at desc limit 1`, customerID)
	return scanSubscription(row)
}

func scanSubscription(row rowScanner) (billing.Subscription, error) {
	var item billing.Subscription
	var grace sql.NullTime
	var lastEventAt time.Time
	var pendingPlanAt sql.NullTime
	if err := row.Scan(&item.ID, &item.UserID, &item.Provider, &item.ProviderCustomerID, &item.ProviderSubscriptionID, &item.PlanID, &item.Status, &item.CurrentPeriodStart, &item.CurrentPeriodEnd, &grace, &item.CancelAtPeriodEnd, &lastEventAt, &item.LastEventID, &item.PendingPlanID, &pendingPlanAt, &item.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return billing.Subscription{}, billing.ErrNotFound
		}
		return billing.Subscription{}, err
	}
	if grace.Valid {
		item.GraceUntil = &grace.Time
	}
	if !lastEventAt.Equal(time.Unix(0, 0).UTC()) {
		item.LastEventAt = lastEventAt
	}
	if pendingPlanAt.Valid {
		item.PendingPlanAt = &pendingPlanAt.Time
	}
	return item, nil
}

func (s *PostgresBillingStore) Save(ctx context.Context, item billing.Subscription) error {
	if item.ID == "" {
		item.ID = "subscription:" + item.UserID
	}
	if err := ensureUser(ctx, s.db, item.UserID); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `insert into subscriptions (id,user_id,provider,provider_customer_id,provider_subscription_id,plan_id,status,current_period_start,current_period_end,grace_until,cancel_at_period_end,last_event_at,last_event_id,pending_plan_id,pending_plan_at,updated_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) on conflict (id) do update set provider=excluded.provider,provider_customer_id=coalesce(excluded.provider_customer_id,subscriptions.provider_customer_id),provider_subscription_id=coalesce(excluded.provider_subscription_id,subscriptions.provider_subscription_id),plan_id=excluded.plan_id,status=excluded.status,current_period_start=excluded.current_period_start,current_period_end=excluded.current_period_end,grace_until=excluded.grace_until,cancel_at_period_end=excluded.cancel_at_period_end,last_event_at=excluded.last_event_at,last_event_id=excluded.last_event_id,pending_plan_id=excluded.pending_plan_id,pending_plan_at=excluded.pending_plan_at,updated_at=excluded.updated_at`, item.ID, item.UserID, item.Provider, nullableString(item.ProviderCustomerID), nullableString(item.ProviderSubscriptionID), item.PlanID, item.Status, item.CurrentPeriodStart, item.CurrentPeriodEnd, item.GraceUntil, item.CancelAtPeriodEnd, nullableTime(item.LastEventAt), nullableString(item.LastEventID), nullableString(item.PendingPlanID), nullableTimePtr(item.PendingPlanAt), item.UpdatedAt)
	return err
}

func (s *PostgresBillingStore) SaveEvent(ctx context.Context, item billing.Subscription) (bool, error) {
	if item.ID == "" {
		item.ID = "subscription:" + item.UserID
	}
	if err := ensureUser(ctx, s.db, item.UserID); err != nil {
		return false, err
	}
	result, err := s.db.ExecContext(ctx, `insert into subscriptions (id,user_id,provider,provider_customer_id,provider_subscription_id,plan_id,status,current_period_start,current_period_end,grace_until,cancel_at_period_end,last_event_at,last_event_id,pending_plan_id,pending_plan_at,updated_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) on conflict (id) do update set provider=excluded.provider,provider_customer_id=coalesce(excluded.provider_customer_id,subscriptions.provider_customer_id),provider_subscription_id=coalesce(excluded.provider_subscription_id,subscriptions.provider_subscription_id),plan_id=excluded.plan_id,status=excluded.status,current_period_start=excluded.current_period_start,current_period_end=excluded.current_period_end,grace_until=excluded.grace_until,cancel_at_period_end=excluded.cancel_at_period_end,last_event_at=excluded.last_event_at,last_event_id=excluded.last_event_id,pending_plan_id=excluded.pending_plan_id,pending_plan_at=excluded.pending_plan_at,updated_at=excluded.updated_at where excluded.last_event_at is null or subscriptions.last_event_at is null or excluded.last_event_at >= subscriptions.last_event_at`, item.ID, item.UserID, item.Provider, nullableString(item.ProviderCustomerID), nullableString(item.ProviderSubscriptionID), item.PlanID, item.Status, item.CurrentPeriodStart, item.CurrentPeriodEnd, item.GraceUntil, item.CancelAtPeriodEnd, nullableTime(item.LastEventAt), nullableString(item.LastEventID), nullableString(item.PendingPlanID), nullableTimePtr(item.PendingPlanAt), item.UpdatedAt)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count > 0, err
}

func (s *PostgresBillingStore) WebhookProcessed(ctx context.Context, provider, eventID string) (bool, error) {
	var processed sql.NullTime
	err := s.db.QueryRowContext(ctx, `select processed_at from webhook_events where provider=$1 and event_id=$2`, provider, eventID).Scan(&processed)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return processed.Valid, err
}

func (s *PostgresBillingStore) MarkWebhookProcessed(ctx context.Context, provider, eventID, eventType string, processedAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `insert into webhook_events (id,provider,event_id,event_type,processed_at,processing_at) values ($1,$2,$3,$4,$5,null) on conflict (provider,event_id) do update set event_type=excluded.event_type,processed_at=excluded.processed_at,processing_at=null`, randomID("webhook"), provider, eventID, eventType, processedAt)
	return err
}

func (s *PostgresBillingStore) ClaimWebhook(ctx context.Context, provider, eventID, eventType string, claimedAt time.Time) (bool, error) {
	var claimed bool
	err := s.db.QueryRowContext(ctx, `with inserted as (insert into webhook_events (id,provider,event_id,event_type,processing_at) values ($1,$2,$3,$4,$5) on conflict (provider,event_id) do nothing returning true), reclaimed as (update webhook_events set processing_at=$5,event_type=$4 where provider=$2 and event_id=$3 and processed_at is null and (processing_at is null or processing_at < $5 - interval '5 minutes') returning true) select coalesce((select true from inserted),(select true from reclaimed),false)`, randomID("webhook"), provider, eventID, eventType, claimedAt).Scan(&claimed)
	return claimed, err
}

func (s *PostgresBillingStore) ReleaseWebhook(ctx context.Context, provider, eventID string) error {
	_, err := s.db.ExecContext(ctx, `update webhook_events set processing_at=null where provider=$1 and event_id=$2 and processed_at is null`, provider, eventID)
	return err
}

// PostgresLedger implements the append-only credit contract. Every mutation
// serializes per user inside a transaction, so two API instances cannot both
// spend the same available balance.
type PostgresLedger struct {
	db  *sql.DB
	now func() time.Time
}

func NewPostgresLedger(db *sql.DB, now func() time.Time) *PostgresLedger {
	if now == nil {
		now = time.Now
	}
	return &PostgresLedger{db: db, now: now}
}

func (l *PostgresLedger) SetPlan(userID, planID string) error {
	plan, ok := credits.PlanByID(planID)
	if !ok {
		return credits.ErrInvalidPlan
	}
	if err := ensureUser(context.Background(), l.db, userID); err != nil {
		return err
	}
	now := l.now().UTC()
	_, err := l.db.Exec(`insert into subscriptions (id,user_id,provider,plan_id,status,current_period_start,current_period_end) values ($1,$2,'paperlens',$3,'active',$4,$5) on conflict (id) do update set plan_id=excluded.plan_id,status='active',updated_at=now()`, "subscription:"+userID, userID, plan.ID, time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC), monthEnd(now))
	return err
}

// SetBillingPeriod is used by the in-memory billing integration. Production
// derives the period from the Stripe-backed subscription row directly.
func (l *PostgresLedger) SetBillingPeriod(userID, planID string, start, end time.Time) error {
	if !end.After(start) {
		return fmt.Errorf("invalid billing period")
	}
	if err := ensureUser(context.Background(), l.db, userID); err != nil {
		return err
	}
	plan, ok := credits.PlanByID(planID)
	if !ok {
		return credits.ErrInvalidPlan
	}
	_, err := l.db.Exec(`insert into subscriptions (id,user_id,provider,plan_id,status,current_period_start,current_period_end) values ($1,$2,'paperlens',$3,'active',$4,$5) on conflict (id) do update set plan_id=excluded.plan_id,current_period_start=excluded.current_period_start,current_period_end=excluded.current_period_end,status='active',updated_at=now()`, "subscription:"+userID, userID, plan.ID, start.UTC(), end.UTC())
	return err
}

func (l *PostgresLedger) Plan(userID string) contract.Plan {
	var id, status, pendingPlan string
	var graceUntil, periodEnd, pendingPlanAt, updatedAt sql.NullTime
	if err := l.db.QueryRow(`select plan_id,status,grace_until,current_period_end,coalesce(pending_plan_id,''),pending_plan_at,updated_at from subscriptions where user_id=$1 and status in ('active','trialing','past_due','canceled') order by updated_at desc limit 1`, userID).Scan(&id, &status, &graceUntil, &periodEnd, &pendingPlan, &pendingPlanAt, &updatedAt); err != nil {
		return mustPlan("free")
	}
	now := l.now().UTC()
	if pendingPlan != "" && pendingPlanAt.Valid && !now.Before(pendingPlanAt.Time) {
		id = pendingPlan
	}
	if effectivePlanExpired(status, graceUntil, periodEnd, updatedAt, now) {
		return mustPlan("free")
	}
	plan, ok := credits.PlanByID(id)
	if !ok {
		return mustPlan("free")
	}
	return plan
}

func (l *PostgresLedger) planTx(tx *sql.Tx, userID string) contract.Plan {
	var id, status, pendingPlan string
	var graceUntil, periodEnd, pendingPlanAt, updatedAt sql.NullTime
	if err := tx.QueryRow(`select plan_id,status,grace_until,current_period_end,coalesce(pending_plan_id,''),pending_plan_at,updated_at from subscriptions where user_id=$1 and status in ('active','trialing','past_due','canceled') order by updated_at desc limit 1`, userID).Scan(&id, &status, &graceUntil, &periodEnd, &pendingPlan, &pendingPlanAt, &updatedAt); err != nil {
		return mustPlan("free")
	}
	now := l.now().UTC()
	if pendingPlan != "" && pendingPlanAt.Valid && !now.Before(pendingPlanAt.Time) {
		id = pendingPlan
	}
	if effectivePlanExpired(status, graceUntil, periodEnd, updatedAt, now) {
		return mustPlan("free")
	}
	plan, ok := credits.PlanByID(id)
	if !ok {
		return mustPlan("free")
	}
	return plan
}

func effectivePlanExpired(status string, graceUntil, periodEnd, updatedAt sql.NullTime, now time.Time) bool {
	switch status {
	case "past_due":
		if graceUntil.Valid {
			return !now.Before(graceUntil.Time)
		}
		return updatedAt.Valid && !now.Before(updatedAt.Time.Add(7*24*time.Hour))
	case "canceled":
		return periodEnd.Valid && !now.Before(periodEnd.Time)
	default:
		return false
	}
}

func (l *PostgresLedger) EnsureGrant(userID string) {
	_ = l.withUserTx(context.Background(), userID, func(tx *sql.Tx) error { return l.ensureGrantTx(tx, userID, l.now().UTC()) })
}

func (l *PostgresLedger) Balance(userID string) contract.CreditBalance {
	now := l.now().UTC()
	if err := l.EnsureGrantTx(userID, now); err != nil {
		return contract.CreditBalance{PlanID: "free", ExpiresAt: monthEnd(now), RateVersion: credits.DefaultRateVersion}
	}
	plan := l.Plan(userID)
	available, reserved, err := l.totals(context.Background(), userID)
	if err != nil {
		return contract.CreditBalance{PlanID: plan.ID, ExpiresAt: monthEnd(now), RateVersion: credits.DefaultRateVersion}
	}
	expiresAt := monthEnd(now)
	if _, end, ok := l.billingPeriod(userID, now); ok {
		expiresAt = end.Add(-time.Nanosecond)
	}
	return contract.CreditBalance{PlanID: plan.ID, Available: available - reserved, Reserved: reserved, ExpiresAt: expiresAt, RateVersion: credits.DefaultRateVersion}
}

func (l *PostgresLedger) Reserve(userID, requestID, planID string, amount int64) error {
	return l.ReserveWithRateVersion(userID, requestID, planID, amount, credits.DefaultRateVersion)
}

func (l *PostgresLedger) ReserveWithRateVersion(userID, requestID, planID string, amount int64, rateVersion string) error {
	if amount <= 0 {
		return fmt.Errorf("reserve amount must be positive")
	}
	plan, ok := credits.PlanByID(planID)
	if !ok {
		return credits.ErrInvalidPlan
	}
	return l.withUserTx(context.Background(), userID, func(tx *sql.Tx) error {
		now := l.now().UTC()
		currentPlan := l.planTx(tx, userID)
		if currentPlan.ID != plan.ID {
			return credits.ErrInvalidPlan
		}
		if err := l.ensureGrantTxWithPlan(tx, userID, now, currentPlan); err != nil {
			return err
		}
		if amount > plan.PerRequestLimit {
			return credits.ErrInsufficient
		}
		available, reserved, err := totalsTx(tx, userID)
		if err != nil {
			return err
		}
		if available-reserved < amount {
			return credits.ErrInsufficient
		}
		monthly, daily, err := usageTx(tx, userID, now)
		if err != nil {
			return err
		}
		if monthly+amount > plan.MonthlyCredits || daily+amount > plan.DailyCredits {
			return credits.ErrInsufficient
		}
		return insertEntry(tx, userID, requestID, credits.Reserve, amount, plan.ID, rateVersion, "")
	})
}

func (l *PostgresLedger) Consume(userID, requestID string, amount int64) error {
	return l.ConsumeWithRateVersion(userID, requestID, amount, credits.DefaultRateVersion)
}

func (l *PostgresLedger) ConsumeWithRateVersion(userID, requestID string, amount int64, rateVersion string) error {
	if amount <= 0 {
		return fmt.Errorf("consume amount must be positive")
	}
	return l.withUserTx(context.Background(), userID, func(tx *sql.Tx) error {
		reserved, err := reservationTx(tx, userID, requestID)
		if err != nil {
			return err
		}
		if reserved <= 0 || amount > reserved {
			return credits.ErrNoReservation
		}
		plan := l.planTx(tx, userID)
		if err := insertEntry(tx, userID, requestID, credits.Consume, amount, plan.ID, rateVersion, ""); err != nil {
			return err
		}
		if amount < reserved {
			return insertEntry(tx, userID, requestID, credits.Release, reserved-amount, plan.ID, rateVersion, "")
		}
		return nil
	})
}

func (l *PostgresLedger) Release(userID, requestID string) error {
	return l.ReleaseWithRateVersion(userID, requestID, credits.DefaultRateVersion)
}

func (l *PostgresLedger) ReleaseWithRateVersion(userID, requestID, rateVersion string) error {
	return l.withUserTx(context.Background(), userID, func(tx *sql.Tx) error {
		reserved, err := reservationTx(tx, userID, requestID)
		if err != nil {
			return err
		}
		if reserved <= 0 {
			return credits.ErrNoReservation
		}
		plan := l.planTx(tx, userID)
		return insertEntry(tx, userID, requestID, credits.Release, reserved, plan.ID, rateVersion, "")
	})
}

func (l *PostgresLedger) Refund(userID, requestID, originalID string, amount int64) error {
	if amount <= 0 || originalID == "" {
		return fmt.Errorf("refund requires a positive amount and original transaction")
	}
	return l.withUserTx(context.Background(), userID, func(tx *sql.Tx) error {
		var consumed int64
		if err := tx.QueryRow(`select amount from credit_ledger where id=$1 and user_id=$2 and type='consume'`, originalID, userID).Scan(&consumed); err != nil {
			return credits.ErrNoReservation
		}
		var refunded int64
		if err := tx.QueryRow(`select coalesce(sum(amount),0) from credit_ledger where user_id=$1 and type='refund' and original_id=$2`, userID, originalID).Scan(&refunded); err != nil {
			return err
		}
		if amount > consumed-refunded {
			return credits.ErrNoReservation
		}
		plan := l.planTx(tx, userID)
		return insertEntryWithOriginal(tx, userID, requestID, credits.Refund, amount, plan.ID, credits.DefaultRateVersion, "admin-refund", originalID)
	})
}

func (l *PostgresLedger) Entries(userID string) []credits.Entry {
	rows, err := l.db.Query(`select id,coalesce(request_id,''),type,amount,plan_id,rate_version,coalesce(source_id,''),coalesce(original_id,''),created_at from credit_ledger where user_id=$1 order by created_at,id`, userID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	entries := make([]credits.Entry, 0)
	for rows.Next() {
		var entry credits.Entry
		var typ string
		if rows.Scan(&entry.ID, &entry.RequestID, &typ, &entry.Amount, &entry.PlanID, &entry.RateVersion, &entry.SourceID, &entry.OriginalID, &entry.CreatedAt) == nil {
			entry.UserID, entry.Type = userID, credits.EntryType(typ)
			entries = append(entries, entry)
		}
	}
	return entries
}

func (l *PostgresLedger) withUserTx(ctx context.Context, userID string, fn func(*sql.Tx) error) error {
	if err := ensureUser(ctx, l.db, userID); err != nil {
		return err
	}
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `select pg_advisory_xact_lock(hashtextextended($1, 0))`, userID); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (l *PostgresLedger) EnsureGrantTx(userID string, now time.Time) error {
	return l.withUserTx(context.Background(), userID, func(tx *sql.Tx) error { return l.ensureGrantTx(tx, userID, now) })
}

func (l *PostgresLedger) ensureGrantTx(tx *sql.Tx, userID string, now time.Time) error {
	return l.ensureGrantTxWithPlan(tx, userID, now, l.planTx(tx, userID))
}

func (l *PostgresLedger) ensureGrantTxWithPlan(tx *sql.Tx, userID string, now time.Time, plan contract.Plan) error {
	periodStart, periodEnd, billingPeriod := billingPeriodTx(tx, userID, now)
	period := now.UTC().Format("2006-01")
	source := "monthly:" + period
	grantID := "grant:" + userID + ":" + period
	if billingPeriod {
		source = "period:" + strconv.FormatInt(periodStart.Unix(), 10) + ":" + strconv.FormatInt(periodEnd.Unix(), 10)
		grantID = "grant:" + userID + ":" + strconv.FormatInt(periodStart.Unix(), 10) + ":" + strconv.FormatInt(periodEnd.Unix(), 10)
	} else {
		periodStart, _ = time.Parse("2006-01", period)
		periodEnd = periodStart.AddDate(0, 1, 0)
	}
	_, err := tx.Exec(`insert into credit_ledger (id,user_id,type,amount,plan_id,rate_version,source_id,created_at) values ($1,$2,'grant',$3,$4,$5,$6,$7) on conflict (user_id,source_id) where type='grant' and source_id is not null do nothing`, grantID, userID, plan.MonthlyCredits, plan.ID, credits.DefaultRateVersion, source, periodStart)
	if err != nil {
		return err
	}
	rows, err := tx.Query(`select id,user_id,amount,plan_id,rate_version,source_id,created_at from credit_ledger where user_id=$1 and type='grant' and (source_id like 'monthly:%' or source_id like 'period:%') and source_id <> $2`, userID, source)
	if err != nil {
		return err
	}
	type grantRow struct {
		id, owner, planID, rateVersion, sourceID string
		amount                                   int64
		created                                  time.Time
	}
	grants := make([]grantRow, 0)
	for rows.Next() {
		var grant grantRow
		if err := rows.Scan(&grant.id, &grant.owner, &grant.amount, &grant.planID, &grant.rateVersion, &grant.sourceID, &grant.created); err != nil {
			return err
		}
		grants = append(grants, grant)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, grant := range grants {
		var expired, consumed int64
		if err := tx.QueryRow(`select coalesce(sum(amount),0) from credit_ledger where user_id=$1 and type='expire' and original_id=$2`, userID, grant.id).Scan(&expired); err != nil {
			return err
		}
		periodStart, periodEnd, parseErr := grantPeriod(grant.sourceID)
		if parseErr != nil {
			return parseErr
		}
		if now.Before(periodEnd) {
			continue
		}
		if err := tx.QueryRow(`select coalesce(sum(amount),0) from credit_ledger where user_id=$1 and type='consume' and created_at >= $2 and created_at < $3`, userID, periodStart, periodEnd).Scan(&consumed); err != nil {
			return err
		}
		if remaining := grant.amount - expired - consumed; remaining > 0 {
			if err := insertEntryWithOriginal(tx, userID, "", credits.Expire, remaining, grant.planID, grant.rateVersion, grant.sourceID, grant.id); err != nil {
				return err
			}
		}
	}
	return rows.Err()
}

func billingPeriodTx(tx *sql.Tx, userID string, now time.Time) (time.Time, time.Time, bool) {
	var start, end time.Time
	err := tx.QueryRow(`select current_period_start,current_period_end from subscriptions where user_id=$1 and current_period_start <= $2 and current_period_end > $2 and status in ('active','trialing','past_due','canceled') order by updated_at desc limit 1`, userID, now).Scan(&start, &end)
	return start.UTC(), end.UTC(), err == nil && end.After(start)
}

func (l *PostgresLedger) billingPeriod(userID string, now time.Time) (time.Time, time.Time, bool) {
	var start, end time.Time
	err := l.db.QueryRow(`select current_period_start,current_period_end from subscriptions where user_id=$1 and current_period_start <= $2 and current_period_end > $2 and status in ('active','trialing','past_due','canceled') order by updated_at desc limit 1`, userID, now).Scan(&start, &end)
	return start.UTC(), end.UTC(), err == nil && end.After(start)
}

func grantPeriod(source string) (time.Time, time.Time, error) {
	if strings.HasPrefix(source, "monthly:") {
		start, err := time.Parse("2006-01", strings.TrimPrefix(source, "monthly:"))
		return start, start.AddDate(0, 1, 0), err
	}
	parts := strings.Split(source, ":")
	if len(parts) != 3 {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid grant period")
	}
	startUnix, startErr := strconv.ParseInt(parts[1], 10, 64)
	endUnix, endErr := strconv.ParseInt(parts[2], 10, 64)
	if startErr != nil || endErr != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid grant period")
	}
	return time.Unix(startUnix, 0).UTC(), time.Unix(endUnix, 0).UTC(), nil
}

func (l *PostgresLedger) totals(ctx context.Context, userID string) (int64, int64, error) {
	return totalsQuery(l.db, ctx, userID)
}

func totalsTx(tx *sql.Tx, userID string) (int64, int64, error) {
	return totalsQuery(tx, context.Background(), userID)
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func totalsQuery(db queryer, ctx context.Context, userID string) (int64, int64, error) {
	var available, reserved int64
	err := db.QueryRowContext(ctx, `select coalesce(sum(case when type in ('grant','refund') then amount when type in ('consume','expire') then -amount else 0 end),0), coalesce(sum(case when type='reserve' then amount when type in ('consume','release') then -amount else 0 end),0) from credit_ledger where user_id=$1`, userID).Scan(&available, &reserved)
	if reserved < 0 {
		reserved = 0
	}
	return available, reserved, err
}

func usageTx(tx *sql.Tx, userID string, now time.Time) (int64, int64, error) {
	var monthly, daily int64
	if start, end, ok := billingPeriodTx(tx, userID, now); ok {
		err := tx.QueryRow(`select coalesce(sum(case when type='reserve' then amount when type='release' then -amount else 0 end) filter (where created_at >= $2 and created_at < $3),0), coalesce(sum(case when type='reserve' then amount when type='release' then -amount else 0 end) filter (where created_at >= date_trunc('day',$4)),0) from credit_ledger where user_id=$1`, userID, start, end, now).Scan(&monthly, &daily)
		return monthly, daily, err
	}
	err := tx.QueryRow(`select coalesce(sum(case when type='reserve' then amount when type='release' then -amount else 0 end) filter (where created_at >= date_trunc('month',$2)),0), coalesce(sum(case when type='reserve' then amount when type='release' then -amount else 0 end) filter (where created_at >= date_trunc('day',$2)),0) from credit_ledger where user_id=$1`, userID, now).Scan(&monthly, &daily)
	return monthly, daily, err
}

func reservationTx(tx *sql.Tx, userID, requestID string) (int64, error) {
	var amount int64
	err := tx.QueryRow(`select coalesce(sum(case when type='reserve' then amount when type in ('consume','release') then -amount else 0 end),0) from credit_ledger where user_id=$1 and request_id=$2`, userID, requestID).Scan(&amount)
	return amount, err
}

func insertEntry(tx *sql.Tx, userID, requestID string, typ credits.EntryType, amount int64, planID, rateVersion, sourceID string) error {
	return insertEntryWithOriginal(tx, userID, requestID, typ, amount, planID, rateVersion, sourceID, "")
}

func insertEntryWithOriginal(tx *sql.Tx, userID, requestID string, typ credits.EntryType, amount int64, planID, rateVersion, sourceID, originalID string) error {
	id := randomID("ledger")
	_, err := tx.Exec(`insert into credit_ledger (id,user_id,request_id,type,amount,plan_id,rate_version,source_id,original_id,created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, userID, nullableString(requestID), typ, amount, planID, rateVersion, nullableString(sourceID), nullableString(originalID), time.Now().UTC())
	return err
}

func ensureUser(ctx context.Context, db *sql.DB, userID string) error {
	hash := sha256.Sum256([]byte(userID))
	_, err := db.ExecContext(ctx, `insert into users (id,email_hash) values ($1,$2) on conflict (id) do nothing`, userID, hex.EncodeToString(hash[:]))
	return err
}

func mustPlan(id string) contract.Plan { plan, _ := credits.PlanByID(id); return plan }

func monthEnd(now time.Time) time.Time {
	now = now.UTC()
	return time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC).Add(-time.Nanosecond)
}

func randomID(prefix string) string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(bytes[:])
}
