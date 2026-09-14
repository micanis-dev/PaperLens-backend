package credits

import (
	"testing"
	"time"
)

func TestRatePolicyValidationAndDefaults(t *testing.T) {
	policy := DefaultRatePolicy()
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	policy.InputTokensPerCredit = 0
	if err := policy.Validate(); err == nil {
		t.Fatal("invalid token unit was accepted")
	}
}

func TestReserveConsumeAndReleaseKeepsLedgerConsistent(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	ledger := NewLedger(func() time.Time { return now })
	if err := ledger.Reserve("user_1", "request_1", "free", 3); err != nil {
		t.Fatal(err)
	}
	if balance := ledger.Balance("user_1"); balance.Available != 17 || balance.Reserved != 3 {
		t.Fatalf("after reserve = %+v", balance)
	}
	if err := ledger.Consume("user_1", "request_1", 2); err != nil {
		t.Fatal(err)
	}
	if balance := ledger.Balance("user_1"); balance.Available != 18 || balance.Reserved != 0 {
		t.Fatalf("after consume = %+v", balance)
	}
	entries := ledger.Entries("user_1")
	if len(entries) != 4 {
		t.Fatalf("entries = %d, want grant/reserve/consume/release", len(entries))
	}
}

func TestRefundIsAppendOnlyAndIdempotent(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	ledger := NewLedger(func() time.Time { return now })
	if err := ledger.Reserve("user_1", "request_1", "free", 3); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Consume("user_1", "request_1", 3); err != nil {
		t.Fatal(err)
	}
	var consumedID string
	for _, entry := range ledger.Entries("user_1") {
		if entry.Type == Consume {
			consumedID = entry.ID
		}
	}
	if consumedID == "" {
		t.Fatal("missing consume entry")
	}
	if err := ledger.Refund("user_1", "refund_1", consumedID, 3); err != nil {
		t.Fatal(err)
	}
	if balance := ledger.Balance("user_1"); balance.Available != 20 || balance.Reserved != 0 {
		t.Fatalf("after refund = %+v", balance)
	}
	if err := ledger.Refund("user_1", "refund_2", consumedID, 3); err == nil {
		t.Fatal("duplicate refund was accepted")
	}
}

func TestRefundAllowsOnlyTheUnrefundedConsumedAmount(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	ledger := NewLedger(func() time.Time { return now })
	if err := ledger.Reserve("user_1", "request_1", "free", 5); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Consume("user_1", "request_1", 5); err != nil {
		t.Fatal(err)
	}
	var consumedID string
	for _, entry := range ledger.Entries("user_1") {
		if entry.Type == Consume {
			consumedID = entry.ID
		}
	}
	if err := ledger.Refund("user_1", "refund_1", consumedID, 2); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Refund("user_1", "refund_2", consumedID, 3); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Refund("user_1", "refund_3", consumedID, 1); err != ErrNoReservation {
		t.Fatalf("over-refund = %v", err)
	}
}

func TestReserveHonorsDailyAndPerRequestLimits(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	ledger := NewLedger(func() time.Time { return now })
	if err := ledger.Reserve("user_1", "request_1", "free", 6); err != ErrInsufficient {
		t.Fatalf("reserve over per-request limit = %v", err)
	}
	if err := ledger.Reserve("user_1", "request_1", "free", 5); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Reserve("user_1", "request_2", "free", 5); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Reserve("user_1", "request_3", "free", 1); err != ErrInsufficient {
		t.Fatalf("reserve over daily limit = %v", err)
	}
}

func TestConsumedCreditsAreNotCountedTwiceAgainstDailyLimit(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	ledger := NewLedger(func() time.Time { return now })
	if err := ledger.Reserve("user_1", "request_1", "free", 5); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Consume("user_1", "request_1", 5); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Reserve("user_1", "request_2", "free", 5); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Reserve("user_1", "request_3", "free", 1); err != ErrInsufficient {
		t.Fatalf("daily usage accepted double-counted request: %v", err)
	}
}

func TestMonthlyGrantIsNotDuplicated(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	ledger := NewLedger(func() time.Time { return now })
	ledger.EnsureGrant("user_1")
	ledger.EnsureGrant("user_1")
	if got := len(ledger.Entries("user_1")); got != 1 {
		t.Fatalf("entries = %d, want one grant", got)
	}
}

func TestPreviousMonthlyGrantExpiresWhenNewPeriodStarts(t *testing.T) {
	now := time.Date(2026, 9, 30, 23, 0, 0, 0, time.UTC)
	ledger := NewLedger(func() time.Time { return now })
	ledger.EnsureGrant("user_1")
	now = time.Date(2026, 10, 1, 0, 1, 0, 0, time.UTC)
	balance := ledger.Balance("user_1")
	if balance.Available != 20 || balance.Reserved != 0 {
		t.Fatalf("new-period balance = %+v", balance)
	}
	var expired int
	for _, entry := range ledger.Entries("user_1") {
		if entry.Type == Expire {
			expired++
		}
	}
	if expired != 1 {
		t.Fatalf("expire entries = %d, want 1", expired)
	}
}

func TestBillingPeriodControlsGrantExpiryAndMonthlyLimit(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	ledger := NewLedger(func() time.Time { return now })
	start := time.Date(2026, 9, 10, 3, 0, 0, 0, time.UTC)
	end := time.Date(2026, 10, 10, 3, 0, 0, 0, time.UTC)
	if err := ledger.SetBillingPeriod("user_1", "plus", start, end); err != nil {
		t.Fatal(err)
	}
	ledger.EnsureGrant("user_1")
	balance := ledger.Balance("user_1")
	if balance.Available != 500 || !balance.ExpiresAt.Equal(end.Add(-time.Nanosecond)) {
		t.Fatalf("billing-period balance = %+v", balance)
	}
	now = end.Add(time.Minute)
	balance = ledger.Balance("user_1")
	if balance.Available != 500 {
		t.Fatalf("new period should not expire into negative balance: %+v", balance)
	}
	var expired int64
	for _, entry := range ledger.Entries("user_1") {
		if entry.Type == Expire {
			expired += entry.Amount
		}
	}
	if expired != 500 {
		t.Fatalf("expired = %d, want 500", expired)
	}
}
