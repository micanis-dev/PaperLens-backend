package translation

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/micanis/paperlens/backend/internal/contract"
	"github.com/micanis/paperlens/backend/internal/credits"
	"github.com/micanis/paperlens/backend/internal/provider"
)

func TestStartIsIdempotent(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	ledger := credits.NewLedger(func() time.Time { return now })
	service := NewService(NewMemoryRepository(), ledger, provider.EchoProvider{}, func() time.Time { return now })
	request := testRequest()
	key := "012345678901234567890123456789012345"
	first, err := service.Start(context.Background(), "user_1", key, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Start(context.Background(), "user_1", key, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("idempotent IDs differ: %s != %s", first.ID, second.ID)
	}
	if first.Result == nil || second.Result != nil {
		t.Fatalf("server retained completed translation result: first=%v second=%v", first.Result != nil, second.Result != nil)
	}
	if balance := ledger.Balance("user_1"); balance.Available != 17 {
		t.Fatalf("balance = %+v, want 17", balance)
	}
}

func TestRatePolicyIsVersionedOnFutureTranslations(t *testing.T) {
	ledger := credits.NewLedger(time.Now)
	service := NewService(NewMemoryRepository(), ledger, provider.EchoProvider{}, time.Now)
	policy := credits.DefaultRatePolicy()
	policy.Version = "2026-10-01"
	policy.InputTokensPerCredit = 10
	if err := service.SetRatePolicy(policy); err != nil {
		t.Fatal(err)
	}
	request := testRequest()
	estimate, err := service.Estimate("user_1", request)
	if err != nil || estimate.RateVersion != policy.Version || estimate.EstimatedCredits != 3 {
		t.Fatalf("estimate=%+v err=%v", estimate, err)
	}
	resource, err := service.Start(context.Background(), "user_1", "012345678901234567890123456789012345", request)
	if err != nil {
		t.Fatal(err)
	}
	if resource.RateVersion != policy.Version {
		t.Fatalf("rate version=%q, want %q", resource.RateVersion, policy.Version)
	}
	for _, entry := range ledger.Entries("user_1") {
		if entry.Type == credits.Reserve || entry.Type == credits.Consume || entry.Type == credits.Release {
			if entry.RateVersion != policy.Version {
				t.Fatalf("entry %s rate version=%q, want %q", entry.Type, entry.RateVersion, policy.Version)
			}
		}
	}
}

func TestManagedModelRateChangesEstimateAndProviderModel(t *testing.T) {
	ledger := credits.NewLedger(time.Now)
	service := NewService(NewMemoryRepository(), ledger, provider.EchoProvider{}, time.Now)
	request := testRequest()
	request.Model = "gpt-6-astra"
	estimate, err := service.Estimate("user_1", request)
	if err != nil {
		t.Fatal(err)
	}
	if estimate.EstimatedCredits != 30 {
		t.Fatalf("astra estimate=%d, want 30", estimate.EstimatedCredits)
	}
	if err := ledger.SetPlan("user_1", "plus"); err != nil {
		t.Fatal(err)
	}
	resource, err := service.Start(context.Background(), "user_1", "012345678901234567890123456789012345", request)
	if err != nil {
		t.Fatal(err)
	}
	if resource.Model != request.Model || resource.Result == nil || resource.Result.Provider.Model != request.Model {
		t.Fatalf("model was not propagated: resource=%+v result=%+v", resource, resource.Result)
	}
}

func TestUnknownManagedModelIsRejected(t *testing.T) {
	service := NewService(NewMemoryRepository(), credits.NewLedger(time.Now), provider.EchoProvider{}, time.Now)
	request := testRequest()
	request.Model = "unknown-model"
	if _, err := service.Estimate("user_1", request); err == nil {
		t.Fatal("unknown managed model was accepted")
	}
}

func TestIdempotencyConflictDoesNotRunProviderAgain(t *testing.T) {
	ledger := credits.NewLedger(time.Now)
	service := NewService(NewMemoryRepository(), ledger, provider.EchoProvider{}, time.Now)
	key := "012345678901234567890123456789012345"
	if _, err := service.Start(context.Background(), "user_1", key, testRequest()); err != nil {
		t.Fatal(err)
	}
	request := testRequest()
	request.Segments[0].Text = "changed"
	if _, err := service.Start(context.Background(), "user_1", key, request); err == nil {
		t.Fatal("expected conflict")
	}
}

func TestConcurrentIdempotencyWaitsForOriginal(t *testing.T) {
	ledger := credits.NewLedger(time.Now)
	translationProvider := &blockingProvider{started: make(chan struct{}), release: make(chan struct{})}
	service := NewService(NewMemoryRepository(), ledger, translationProvider, time.Now)
	key := "012345678901234567890123456789012345"
	firstDone := make(chan *contract.TranslationResource, 1)
	firstErr := make(chan error, 1)
	go func() {
		result, err := service.Start(context.Background(), "user_1", key, testRequest())
		firstDone <- result
		firstErr <- err
	}()
	<-translationProvider.started
	secondDone := make(chan *contract.TranslationResource, 1)
	go func() {
		result, err := service.Start(context.Background(), "user_1", key, testRequest())
		if err != nil {
			firstErr <- err
		}
		secondDone <- result
	}()
	select {
	case <-secondDone:
		t.Fatal("duplicate returned before original completed")
	case <-time.After(30 * time.Millisecond):
	}
	close(translationProvider.release)
	first := <-firstDone
	if err := <-firstErr; err != nil {
		t.Fatal(err)
	}
	second := <-secondDone
	if first.ID != second.ID || translationProvider.calls.Load() != 1 {
		t.Fatalf("first=%v second=%v providerCalls=%d", first.ID, second.ID, translationProvider.calls.Load())
	}
}

func TestCancelWinsAgainstProviderCompletion(t *testing.T) {
	ledger := credits.NewLedger(time.Now)
	translationProvider := &blockingProvider{started: make(chan struct{}), release: make(chan struct{})}
	service := NewService(NewMemoryRepository(), ledger, translationProvider, time.Now)
	result := make(chan *contract.TranslationResource, 1)
	errCh := make(chan error, 1)
	go func() {
		value, err := service.Start(context.Background(), "user_1", "012345678901234567890123456789012345", testRequest())
		result <- value
		errCh <- err
	}()
	<-translationProvider.started
	resource, err := service.Cancel("user_1", "missing")
	if err != ErrNotFound || resource != nil {
		t.Fatalf("missing cancel resource=%v err=%v", resource, err)
	}
	// Find the request ID through the idempotency lookup by canceling the
	// resource created by the in-flight request.
	service.startMu.Lock()
	inFlight, findErr := service.repository.FindByIdempotency("user_1", "012345678901234567890123456789012345")
	service.startMu.Unlock()
	if findErr != nil {
		t.Fatal(findErr)
	}
	canceled, err := service.Cancel("user_1", inFlight.ID)
	if err != nil || canceled.Status != contract.StatusCanceled {
		t.Fatalf("canceled=%+v err=%v", canceled, err)
	}
	value := <-result
	if err := <-errCh; err != nil || value.Status != contract.StatusCanceled {
		t.Fatalf("start value=%+v err=%v", value, err)
	}
	if balance := ledger.Balance("user_1"); balance.Available != 20 || balance.Reserved != 0 {
		t.Fatalf("balance after cancel=%+v", balance)
	}
}

func TestReconcileStaleRequestReleasesReservation(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	ledger := credits.NewLedger(func() time.Time { return now })
	repository := NewMemoryRepository()
	resource := &contract.TranslationResource{
		ID: "tr_stale", UserID: "user_1", IdempotencyKey: "012345678901234567890123456789012345",
		RequestHash: "hash", Mode: contract.ModePaperLensManaged, Model: "echo",
		RateVersion: credits.DefaultRateVersion, Status: contract.StatusRunning,
		CreatedAt: now.Add(-StaleTranslationAge - time.Second), SourceLanguage: "en",
		TargetLanguage: "ja", SegmentCount: 1, CreditsReserved: 3,
	}
	if err := ledger.Reserve(resource.UserID, resource.ID, "free", resource.CreditsReserved); err != nil {
		t.Fatal(err)
	}
	if err := repository.Create(resource); err != nil {
		t.Fatal(err)
	}
	service := NewService(repository, ledger, provider.EchoProvider{}, func() time.Time { return now })
	if err := service.ReconcileStale(context.Background(), now.Add(-StaleTranslationAge)); err != nil {
		t.Fatal(err)
	}
	recovered, err := repository.Get(resource.UserID, resource.ID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Status != contract.StatusFailed || recovered.ErrorCode != contract.ErrProviderUnavailable {
		t.Fatalf("recovered resource=%+v", recovered)
	}
	if balance := ledger.Balance(resource.UserID); balance.Reserved != 0 || balance.Available != 20 {
		t.Fatalf("balance after reconciliation=%+v", balance)
	}
}

type blockingProvider struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (p *blockingProvider) Name() string  { return "blocking" }
func (p *blockingProvider) Model() string { return "blocking" }
func (p *blockingProvider) Translate(ctx context.Context, request provider.Request) (contract.TranslationResult, error) {
	p.calls.Add(1)
	select {
	case p.started <- struct{}{}:
	default:
	}
	select {
	case <-p.release:
		return provider.EchoProvider{}.Translate(ctx, request)
	case <-ctx.Done():
		return contract.TranslationResult{}, ctx.Err()
	}
}

func testRequest() contract.TranslationRequest {
	return contract.TranslationRequest{DocumentID: "paper_1", SourceLanguage: "en", TargetLanguage: "ja", PreserveFormatting: true, Segments: []contract.TranslationSegment{{ID: "seg_1", PageNumber: 1, Order: 0, Text: "hello world", TextHash: "hash"}}}
}
