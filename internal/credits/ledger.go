package credits

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/micanis/paperlens/backend/internal/contract"
)

const DefaultRateVersion = "2026-09-01"
const DefaultPriceVersion = "2026-09-01"

// RatePolicy is versioned so a later pricing change never changes the
// accounting of an already completed translation. Costs are expressed in
// micro-USD per one million tokens to avoid floating point values in the
// administrative API and database.
type RatePolicy struct {
	Version               string               `json:"version"`
	InputTokensPerCredit  int64                `json:"inputTokensPerCredit"`
	OutputTokensPerCredit int64                `json:"outputTokensPerCredit"`
	OutputWeight          int64                `json:"outputWeight"`
	Models                map[string]ModelCost `json:"models"`
}

type ModelCost struct {
	InputMicroUSDPerMillion  int64 `json:"inputMicroUsdPerMillion"`
	OutputMicroUSDPerMillion int64 `json:"outputMicroUsdPerMillion"`
}

func DefaultRatePolicy() RatePolicy {
	return RatePolicy{
		Version: DefaultRateVersion, InputTokensPerCredit: 1000,
		OutputTokensPerCredit: 1000, OutputWeight: 2,
		Models: map[string]ModelCost{"default": {InputMicroUSDPerMillion: 0, OutputMicroUSDPerMillion: 0}},
	}
}

func (p RatePolicy) Validate() error {
	if strings.TrimSpace(p.Version) == "" || len(p.Version) > 64 {
		return fmt.Errorf("rate policy version is required and must be at most 64 characters")
	}
	if p.InputTokensPerCredit <= 0 || p.OutputTokensPerCredit <= 0 || p.OutputWeight <= 0 {
		return fmt.Errorf("rate policy token units and output weight must be positive")
	}
	if len(p.Models) == 0 || len(p.Models) > 100 {
		return fmt.Errorf("rate policy must contain between 1 and 100 models")
	}
	for model, cost := range p.Models {
		if strings.TrimSpace(model) == "" || len(model) > 128 || cost.InputMicroUSDPerMillion < 0 || cost.OutputMicroUSDPerMillion < 0 {
			return fmt.Errorf("rate policy contains an invalid model cost")
		}
	}
	return nil
}

var (
	ErrInsufficient  = errors.New("insufficient credits")
	ErrInvalidPlan   = errors.New("invalid plan")
	ErrNoReservation = errors.New("no active reservation")
)

type EntryType string

const (
	Grant   EntryType = "grant"
	Reserve EntryType = "reserve"
	Consume EntryType = "consume"
	Release EntryType = "release"
	Refund  EntryType = "refund"
	Expire  EntryType = "expire"
)

type Entry struct {
	ID          string
	UserID      string
	RequestID   string
	Type        EntryType
	Amount      int64
	PlanID      string
	RateVersion string
	SourceID    string
	CreatedAt   time.Time
	OriginalID  string
}

type Ledger struct {
	mu      sync.Mutex
	entries []Entry
	plans   map[string]string
	periods map[string]billingPeriod
	now     func() time.Time
	nextID  uint64
}

type billingPeriod struct {
	start time.Time
	end   time.Time
}

// Store is the persistence boundary used by the API and translation service.
// The in-memory implementation is useful for local development; production
// uses the same operations backed by PostgreSQL.
type Store interface {
	SetPlan(userID, planID string) error
	Plan(userID string) contract.Plan
	EnsureGrant(userID string)
	Balance(userID string) contract.CreditBalance
	Reserve(userID, requestID, planID string, amount int64) error
	Consume(userID, requestID string, amount int64) error
	Release(userID, requestID string) error
	Refund(userID, requestID, originalID string, amount int64) error
	Entries(userID string) []Entry
}

// BillingPeriodStore is an optional synchronization boundary from billing.
// Users without a subscription continue to use calendar-month grants.
type BillingPeriodStore interface {
	SetBillingPeriod(userID, planID string, start, end time.Time) error
}

// VersionedStore is implemented by ledgers that can preserve the rate policy
// version on reservation lifecycle entries. Store remains backwards
// compatible for lightweight integrations and tests.
type VersionedStore interface {
	ReserveWithRateVersion(userID, requestID, planID string, amount int64, rateVersion string) error
	ConsumeWithRateVersion(userID, requestID string, amount int64, rateVersion string) error
	ReleaseWithRateVersion(userID, requestID, rateVersion string) error
}

func NewLedger(now func() time.Time) *Ledger {
	if now == nil {
		now = time.Now
	}
	return &Ledger{plans: make(map[string]string), periods: make(map[string]billingPeriod), now: now}
}

func PlanCatalog() []contract.Plan {
	return []contract.Plan{
		{ID: "free", MonthlyPriceYen: 0, PriceVersion: DefaultPriceVersion, MonthlyCredits: 20, DailyCredits: 10, PerRequestLimit: 5, ConcurrentLimit: 1, Priority: "normal"},
		{ID: "plus", MonthlyPriceYen: 980, PriceVersion: DefaultPriceVersion, MonthlyCredits: 500, DailyCredits: 100, PerRequestLimit: 100, ConcurrentLimit: 2, Priority: "normal"},
		{ID: "pro", MonthlyPriceYen: 2_980, PriceVersion: DefaultPriceVersion, MonthlyCredits: 2_000, DailyCredits: 500, PerRequestLimit: 500, ConcurrentLimit: 4, Priority: "high"},
		{ID: "ultra", MonthlyPriceYen: 9_800, PriceVersion: DefaultPriceVersion, MonthlyCredits: 10_000, DailyCredits: 2_000, PerRequestLimit: 2_000, ConcurrentLimit: 8, Priority: "highest"},
	}
}

func PlanByID(id string) (contract.Plan, bool) {
	for _, plan := range PlanCatalog() {
		if plan.ID == id {
			return plan, true
		}
	}
	return contract.Plan{}, false
}

func (l *Ledger) SetPlan(userID, planID string) error {
	if _, ok := PlanByID(planID); !ok {
		return ErrInvalidPlan
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.plans[userID] = planID
	return nil
}

func (l *Ledger) SetBillingPeriod(userID, planID string, start, end time.Time) error {
	if err := l.SetPlan(userID, planID); err != nil {
		return err
	}
	if start.IsZero() || end.IsZero() || !end.After(start) {
		return fmt.Errorf("invalid billing period")
	}
	l.mu.Lock()
	l.periods[userID] = billingPeriod{start: start.UTC(), end: end.UTC()}
	l.mu.Unlock()
	return nil
}

func (l *Ledger) Plan(userID string) contract.Plan {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.planLocked(userID)
}

func (l *Ledger) EnsureGrant(userID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ensureGrantLocked(userID, l.now())
}

func (l *Ledger) Balance(userID string) contract.CreditBalance {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.ensureGrantLocked(userID, now)
	plan := l.planLocked(userID)
	available, reserved := l.availableAndReservedLocked(userID)
	expiresAt := monthEnd(now)
	if period, ok := l.periods[userID]; ok && period.end.After(now.UTC()) {
		expiresAt = period.end.Add(-time.Nanosecond)
	}
	return contract.CreditBalance{
		PlanID:      plan.ID,
		Available:   available - reserved,
		Reserved:    reserved,
		ExpiresAt:   expiresAt,
		RateVersion: DefaultRateVersion,
	}
}

func (l *Ledger) Reserve(userID, requestID, planID string, amount int64) error {
	return l.ReserveWithRateVersion(userID, requestID, planID, amount, DefaultRateVersion)
}

func (l *Ledger) ReserveWithRateVersion(userID, requestID, planID string, amount int64, rateVersion string) error {
	if amount <= 0 {
		return fmt.Errorf("reserve amount must be positive")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	plan, ok := PlanByID(planID)
	if !ok || l.planLocked(userID).ID != planID {
		return ErrInvalidPlan
	}
	now := l.now()
	l.ensureGrantLocked(userID, now)
	if amount > plan.PerRequestLimit {
		return ErrInsufficient
	}
	available, reserved := l.availableAndReservedLocked(userID)
	if available-reserved < amount {
		return ErrInsufficient
	}
	if l.periodUsageLocked(userID, now, false)+amount > plan.MonthlyCredits || l.periodUsageLocked(userID, now, true)+amount > plan.DailyCredits {
		return ErrInsufficient
	}
	l.entries = append(l.entries, l.newEntry(userID, requestID, Reserve, amount, planID, rateVersion, ""))
	return nil
}

func (l *Ledger) Consume(userID, requestID string, amount int64) error {
	return l.ConsumeWithRateVersion(userID, requestID, amount, DefaultRateVersion)
}

func (l *Ledger) ConsumeWithRateVersion(userID, requestID string, amount int64, rateVersion string) error {
	if amount <= 0 {
		return fmt.Errorf("consume amount must be positive")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	reserved := l.activeReservationLocked(userID, requestID)
	if reserved <= 0 || amount > reserved {
		return ErrNoReservation
	}
	l.entries = append(l.entries, l.newEntry(userID, requestID, Consume, amount, l.planLocked(userID).ID, rateVersion, ""))
	if amount < reserved {
		l.entries = append(l.entries, l.newEntry(userID, requestID, Release, reserved-amount, l.planLocked(userID).ID, rateVersion, ""))
	}
	return nil
}

func (l *Ledger) Release(userID, requestID string) error {
	return l.ReleaseWithRateVersion(userID, requestID, DefaultRateVersion)
}

func (l *Ledger) ReleaseWithRateVersion(userID, requestID, rateVersion string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	reserved := l.activeReservationLocked(userID, requestID)
	if reserved <= 0 {
		return ErrNoReservation
	}
	l.entries = append(l.entries, l.newEntry(userID, requestID, Release, reserved, l.planLocked(userID).ID, rateVersion, ""))
	return nil
}

// Refund appends a compensating entry for a consumed transaction. OriginalID
// makes the operation idempotent for an administrator retry.
func (l *Ledger) Refund(userID, requestID, originalID string, amount int64) error {
	if amount <= 0 {
		return fmt.Errorf("refund amount must be positive")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if strings.TrimSpace(originalID) == "" {
		return fmt.Errorf("original transaction is required")
	}
	var consumed, refunded int64
	for _, entry := range l.entries {
		if entry.UserID == userID && entry.ID == originalID && entry.Type == Consume {
			consumed = entry.Amount
		}
		if entry.UserID == userID && entry.Type == Refund && entry.OriginalID == originalID {
			refunded += entry.Amount
		}
	}
	if consumed == 0 || amount > consumed-refunded {
		return ErrNoReservation
	}
	entry := l.newEntry(userID, requestID, Refund, amount, l.planLocked(userID).ID, DefaultRateVersion, "admin-refund")
	entry.OriginalID = originalID
	l.entries = append(l.entries, entry)
	return nil
}

func (l *Ledger) Entries(userID string) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	result := make([]Entry, 0)
	for _, entry := range l.entries {
		if entry.UserID == userID {
			result = append(result, entry)
		}
	}
	return result
}

func (l *Ledger) planLocked(userID string) contract.Plan {
	planID := l.plans[userID]
	if planID == "" {
		planID = "free"
	}
	plan, _ := PlanByID(planID)
	return plan
}

func (l *Ledger) ensureGrantLocked(userID string, now time.Time) {
	plan := l.planLocked(userID)
	sourceID := l.currentGrantSource(userID, now)
	l.expirePriorGrantsLocked(userID, sourceID, now)
	for _, entry := range l.entries {
		if entry.UserID == userID && entry.Type == Grant && entry.SourceID == sourceID {
			return
		}
	}
	l.entries = append(l.entries, l.newEntry(userID, "", Grant, plan.MonthlyCredits, plan.ID, DefaultRateVersion, sourceID))
}

func (l *Ledger) expirePriorGrantsLocked(userID, currentSource string, now time.Time) {
	for _, grant := range l.entries {
		if grant.UserID != userID || grant.Type != Grant || !isGrantSource(grant.SourceID) || grant.SourceID == currentSource {
			continue
		}
		if end, ok := grantPeriodEnd(grant.SourceID); ok && now.UTC().Before(end) {
			continue
		}
		alreadyExpired := int64(0)
		consumed := int64(0)
		for _, entry := range l.entries {
			if entry.UserID != userID || !entryInGrantPeriod(entry, grant.SourceID) {
				continue
			}
			if entry.Type == Consume {
				consumed += entry.Amount
			}
		}
		for _, entry := range l.entries {
			if entry.UserID == userID && entry.Type == Expire && entry.OriginalID == grant.ID {
				alreadyExpired += entry.Amount
			}
		}
		remaining := grant.Amount - consumed - alreadyExpired
		if remaining > 0 {
			entry := l.newEntry(userID, "", Expire, remaining, grant.PlanID, grant.RateVersion, grant.SourceID)
			entry.OriginalID = grant.ID
			l.entries = append(l.entries, entry)
		}
	}
}

func (l *Ledger) currentGrantSource(userID string, now time.Time) string {
	if period, ok := l.periods[userID]; ok && !now.UTC().Before(period.start) && now.UTC().Before(period.end) {
		return "period:" + strconv.FormatInt(period.start.Unix(), 10) + ":" + strconv.FormatInt(period.end.Unix(), 10)
	}
	return "monthly:" + now.UTC().Format("2006-01")
}

func isGrantSource(source string) bool {
	return strings.HasPrefix(source, "monthly:") || strings.HasPrefix(source, "period:")
}

func grantPeriodEnd(source string) (time.Time, bool) {
	if strings.HasPrefix(source, "monthly:") {
		start, err := time.Parse("2006-01", strings.TrimPrefix(source, "monthly:"))
		return start.AddDate(0, 1, 0), err == nil
	}
	parts := strings.Split(source, ":")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	end, err := strconv.ParseInt(parts[2], 10, 64)
	return time.Unix(end, 0).UTC(), err == nil
}

func entryInGrantPeriod(entry Entry, source string) bool {
	if strings.HasPrefix(source, "monthly:") {
		start, err := time.Parse("2006-01", strings.TrimPrefix(source, "monthly:"))
		return err == nil && !entry.CreatedAt.Before(start) && entry.CreatedAt.Before(start.AddDate(0, 1, 0))
	}
	parts := strings.Split(source, ":")
	if len(parts) != 3 {
		return false
	}
	start, startErr := strconv.ParseInt(parts[1], 10, 64)
	end, endErr := strconv.ParseInt(parts[2], 10, 64)
	return startErr == nil && endErr == nil && !entry.CreatedAt.Before(time.Unix(start, 0)) && entry.CreatedAt.Before(time.Unix(end, 0))
}

func (l *Ledger) availableAndReservedLocked(userID string) (int64, int64) {
	var available, reserved int64
	for _, entry := range l.entries {
		if entry.UserID != userID {
			continue
		}
		switch entry.Type {
		case Grant, Refund:
			available += entry.Amount
		case Consume, Expire:
			available -= entry.Amount
		case Reserve:
			reserved += entry.Amount
		}
	}
	for _, entry := range l.entries {
		if entry.UserID != userID {
			continue
		}
		if entry.Type == Consume || entry.Type == Release {
			reserved -= entry.Amount
		}
	}
	return available, max(0, reserved)
}

func (l *Ledger) activeReservationLocked(userID, requestID string) int64 {
	var reserved int64
	for _, entry := range l.entries {
		if entry.UserID != userID || entry.RequestID != requestID {
			continue
		}
		switch entry.Type {
		case Reserve:
			reserved += entry.Amount
		case Consume, Release:
			reserved -= entry.Amount
		}
	}
	return max(0, reserved)
}

func (l *Ledger) periodUsageLocked(userID string, now time.Time, daily bool) int64 {
	var consumed, reserved int64
	for _, entry := range l.entries {
		if entry.UserID != userID {
			continue
		}
		if entry.Type != Consume && entry.Type != Reserve && entry.Type != Release {
			continue
		}
		if daily && !sameDay(entry.CreatedAt, now) {
			continue
		}
		if !daily {
			if period, ok := l.periods[userID]; ok {
				if entry.CreatedAt.Before(period.start) || !entry.CreatedAt.Before(period.end) {
					continue
				}
			} else if entry.CreatedAt.UTC().Format("2006-01") != now.UTC().Format("2006-01") {
				continue
			}
		}
		switch entry.Type {
		case Consume:
			consumed += entry.Amount
			reserved -= entry.Amount
		case Reserve:
			reserved += entry.Amount
		case Release:
			reserved -= entry.Amount
		}
	}
	return consumed + max(0, reserved)
}

func (l *Ledger) newEntry(userID, requestID string, kind EntryType, amount int64, planID, rateVersion, sourceID string) Entry {
	l.nextID++
	return Entry{ID: fmt.Sprintf("ledger_%d", l.nextID), UserID: userID, RequestID: requestID, Type: kind, Amount: amount, PlanID: planID, RateVersion: rateVersion, SourceID: sourceID, CreatedAt: l.now()}
}

func sameDay(a, b time.Time) bool {
	a, b = a.UTC(), b.UTC()
	y1, m1, d1 := a.Date()
	y2, m2, d2 := b.Date()
	return y1 == y2 && m1 == m2 && d1 == d2
}

func monthEnd(now time.Time) time.Time {
	now = now.UTC()
	return time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC).Add(-time.Nanosecond)
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
