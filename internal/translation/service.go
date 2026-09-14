package translation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/micanis/paperlens/backend/internal/contract"
	"github.com/micanis/paperlens/backend/internal/credits"
	"github.com/micanis/paperlens/backend/internal/provider"
)

var (
	ErrNotFound = errors.New("translation not found")
	ErrConflict = errors.New("idempotency key conflict")
)

type Repository interface {
	Create(*contract.TranslationResource) error
	Get(userID, id string) (*contract.TranslationResource, error)
	FindByIdempotency(userID, key string) (*contract.TranslationResource, error)
	Update(*contract.TranslationResource) error
}

// StaleRepository is an optional durable recovery boundary. A process crash
// can leave only metadata in a running state; implementations expose those
// rows so the service can release their reservation and make them retryable.
type StaleRepository interface {
	ListRunningBefore(context.Context, time.Time) ([]*contract.TranslationResource, error)
}

type MemoryRepository struct {
	mu    sync.RWMutex
	items map[string]*contract.TranslationResource
	byKey map[string]string
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{items: make(map[string]*contract.TranslationResource), byKey: make(map[string]string)}
}

func (r *MemoryRepository) Create(item *contract.TranslationResource) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.items[item.ID]; exists {
		return fmt.Errorf("translation %s already exists", item.ID)
	}
	if item.IdempotencyKey != "" {
		key := idempotencyKey(item.UserID, item.IdempotencyKey)
		if existing, exists := r.byKey[key]; exists {
			return fmt.Errorf("idempotency key already exists: %s", existing)
		}
		r.byKey[key] = item.ID
	}
	r.items[item.ID] = cloneMetadata(item)
	return nil
}

func (r *MemoryRepository) Get(userID, id string) (*contract.TranslationResource, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	item, ok := r.items[id]
	if !ok || item.UserID != userID {
		return nil, ErrNotFound
	}
	return clone(item), nil
}

func (r *MemoryRepository) FindByIdempotency(userID, key string) (*contract.TranslationResource, error) {
	if key == "" {
		return nil, ErrNotFound
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.byKey[idempotencyKey(userID, key)]
	if !ok {
		return nil, ErrNotFound
	}
	return clone(r.items[id]), nil
}

func (r *MemoryRepository) Update(item *contract.TranslationResource) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.items[item.ID]; !ok {
		return ErrNotFound
	}
	// Completed translation text is returned directly to the caller and is
	// retained by the browser. The server-side repository keeps only the
	// metadata needed for idempotency and status lookup.
	r.items[item.ID] = cloneMetadata(item)
	return nil
}

func (r *MemoryRepository) ListRunningBefore(_ context.Context, before time.Time) ([]*contract.TranslationResource, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	items := make([]*contract.TranslationResource, 0)
	for _, item := range r.items {
		if (item.Status == contract.StatusRunning || item.Status == contract.StatusPending) && item.CreatedAt.Before(before) {
			items = append(items, clone(item))
		}
	}
	return items, nil
}

type Service struct {
	repository Repository
	ledger     credits.Store
	provider   provider.Provider
	now        func() time.Time
	rateMu     sync.RWMutex
	ratePolicy credits.RatePolicy
	startMu    sync.Mutex
	activeMu   sync.Mutex
	active     map[string]int
	jobMu      sync.Mutex
	jobs       map[string]context.CancelFunc
	observer   Observer
}

const StaleTranslationAge = 5 * time.Minute

// Observer is intentionally small so the translation use case does not know
// which metrics or tracing backend is deployed around it.
type Observer interface {
	ObserveProviderLatency(provider string, elapsed time.Duration)
	ObserveTranslationFailure()
	ObserveTranslationSuccess()
	ObserveLedgerInconsistency()
	ObserveManagedUsage(model string, inputTokens, outputTokens int64, cost credits.ModelCost)
}

type managedAdmission interface {
	AllowManagedTranslation() bool
}

func NewService(repository Repository, ledger credits.Store, translationProvider provider.Provider, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{repository: repository, ledger: ledger, provider: translationProvider, now: now, ratePolicy: credits.DefaultRatePolicy(), active: make(map[string]int), jobs: make(map[string]context.CancelFunc)}
}

func (s *Service) WithObserver(observer Observer) *Service {
	s.observer = observer
	return s
}

// SetRatePolicy changes only future requests. The selected version is copied
// into each request resource and ledger entry, so historical accounting stays
// reproducible after an administrator publishes a new policy.
func (s *Service) SetRatePolicy(policy credits.RatePolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	s.rateMu.Lock()
	s.ratePolicy = cloneRatePolicy(policy)
	s.rateMu.Unlock()
	return nil
}

func (s *Service) RatePolicy() credits.RatePolicy {
	s.rateMu.RLock()
	defer s.rateMu.RUnlock()
	return cloneRatePolicy(s.ratePolicy)
}

type Estimate struct {
	InputTokens           int64         `json:"inputTokens"`
	EstimatedOutputTokens int64         `json:"estimatedOutputTokens"`
	EstimatedCredits      int64         `json:"estimatedCredits"`
	Plan                  contract.Plan `json:"plan"`
	RateVersion           string        `json:"rateVersion"`
}

func (s *Service) Estimate(userID string, request contract.TranslationRequest) (Estimate, error) {
	if err := contract.ValidateTranslationRequest(request); err != nil {
		return Estimate{}, &RequestError{Code: validationErrorCode(err), Message: err.Error(), Retryable: false}
	}
	plan := s.ledger.Plan(userID)
	input, output := estimateUsage(request)
	policy := s.RatePolicy()
	creditEstimate := creditsFor(policy, input, output)
	return Estimate{InputTokens: input, EstimatedOutputTokens: output, EstimatedCredits: creditEstimate, Plan: plan, RateVersion: policy.Version}, nil
}

func (s *Service) Start(ctx context.Context, userID, idempotencyKey string, request contract.TranslationRequest) (*contract.TranslationResource, error) {
	return s.start(ctx, userID, idempotencyKey, request, nil, nil)
}

// StartWithStarted is the streaming boundary. The callback fires after the
// request and its reservation have been created, but before the provider is
// called, so an SSE client receives a real translation ID immediately.
func (s *Service) StartWithStarted(ctx context.Context, userID, idempotencyKey string, request contract.TranslationRequest, onStarted func(string)) (*contract.TranslationResource, error) {
	return s.start(ctx, userID, idempotencyKey, request, onStarted, nil)
}

func (s *Service) StartWithEvents(ctx context.Context, userID, idempotencyKey string, request contract.TranslationRequest, onStarted func(string), onSegment func(contract.TranslatedSegment) error) (*contract.TranslationResource, error) {
	return s.start(ctx, userID, idempotencyKey, request, onStarted, onSegment)
}

func (s *Service) start(ctx context.Context, userID, idempotencyKey string, request contract.TranslationRequest, onStarted func(string), onSegment func(contract.TranslatedSegment) error) (*contract.TranslationResource, error) {
	if len(idempotencyKey) < 36 || len(idempotencyKey) > 128 {
		return nil, &RequestError{Code: contract.ErrInvalidRequest, Message: "Idempotency-Key must be 36 to 128 characters", Retryable: false}
	}
	if err := contract.ValidateTranslationRequest(request); err != nil {
		return nil, &RequestError{Code: validationErrorCode(err), Message: err.Error(), Retryable: false}
	}
	if admission, ok := s.observer.(managedAdmission); ok && !admission.AllowManagedTranslation() {
		return nil, &RequestError{Code: contract.ErrProviderUnavailable, Message: "managed translation is temporarily paused", Retryable: true, HTTPStatus: 503}
	}
	hash := contract.HashRequest(request)

	estimate, err := s.Estimate(userID, request)
	if err != nil {
		if typed, ok := err.(*RequestError); ok {
			return nil, typed
		}
		return nil, &RequestError{Code: validationErrorCode(err), Message: err.Error(), Retryable: false}
	}
	plan := estimate.Plan
	if !requestModeConsumesCredits(request) {
		plan = s.ledger.Plan(userID)
	}
	policy := s.RatePolicy()
	// Serialize only the lookup/create boundary. The provider call happens
	// outside this lock so independent requests can use the plan's concurrency.
	s.startMu.Lock()
	if existing, findErr := s.repository.FindByIdempotency(userID, idempotencyKey); findErr == nil {
		s.startMu.Unlock()
		if existing.RequestHash != hash {
			return nil, &RequestError{Code: contract.ErrIdempotencyConflict, Message: "Idempotency-Key was used with a different request", Retryable: false}
		}
		if existing.Status == contract.StatusRunning || existing.Status == contract.StatusPending {
			return s.waitForCompletion(ctx, userID, existing.ID)
		}
		return existing, nil
	}
	if !s.acquire(userID, plan.ConcurrentLimit) {
		s.startMu.Unlock()
		return nil, &RequestError{Code: contract.ErrRateLimited, Message: "translation concurrency limit reached", Retryable: true}
	}
	defer s.release(userID)
	id := newID("tr")
	if plan.ID != "" && requestModeConsumesCredits(request) {
		if err := s.reserve(userID, id, plan.ID, estimate.EstimatedCredits, policy.Version); err != nil {
			s.startMu.Unlock()
			return nil, &RequestError{Code: contract.ErrInsufficientCredits, Message: "not enough credits for this translation", Retryable: false}
		}
	}
	now := s.now()
	resource := &contract.TranslationResource{ID: id, UserID: userID, IdempotencyKey: idempotencyKey, RequestHash: hash, Mode: contract.ModePaperLensManaged, Model: s.provider.Model(), RateVersion: policy.Version, Status: contract.StatusRunning, CreatedAt: now, SourceLanguage: request.SourceLanguage, TargetLanguage: request.TargetLanguage, SegmentCount: len(request.Segments), CreditsReserved: estimate.EstimatedCredits}
	if err := s.repository.Create(resource); err != nil {
		if requestModeConsumesCredits(request) {
			_ = s.releaseCredits(userID, id, policy.Version)
		}
		s.startMu.Unlock()
		// A durable repository can reject this create because another API
		// instance won the unique (user, idempotency_key) race. Resolve that
		// race through the same idempotency contract instead of exposing a
		// database constraint error or charging a second request.
		if existing, findErr := s.repository.FindByIdempotency(userID, idempotencyKey); findErr == nil {
			if existing.RequestHash != hash {
				return nil, &RequestError{Code: contract.ErrIdempotencyConflict, Message: "Idempotency-Key was used with a different request", Retryable: false}
			}
			if existing.Status == contract.StatusRunning || existing.Status == contract.StatusPending {
				return s.waitForCompletion(ctx, userID, existing.ID)
			}
			return existing, nil
		}
		return nil, err
	}
	providerCtx, cancel := context.WithCancel(ctx)
	s.jobMu.Lock()
	s.jobs[id] = cancel
	s.jobMu.Unlock()
	// Register the cancellation function before notifying the streaming
	// client. The client can call /cancel as soon as it receives `started`; if
	// registration happened afterwards, that first cancellation could mark the
	// row canceled without actually stopping the provider request.
	if onStarted != nil {
		onStarted(id)
	}
	s.startMu.Unlock()
	defer func() {
		cancel()
		s.jobMu.Lock()
		delete(s.jobs, id)
		s.jobMu.Unlock()
	}()

	providerResult, err := s.translateWithRetry(providerCtx, provider.Request{RequestID: id, Mode: contract.ModePaperLensManaged, Model: s.provider.Model(), SourceLanguage: request.SourceLanguage, TargetLanguage: request.TargetLanguage, Segments: request.Segments, Glossary: request.Glossary, PreserveFormatting: request.PreserveFormatting}, onSegment)
	if err != nil {
		s.jobMu.Lock()
		if current, getErr := s.repository.Get(userID, id); getErr == nil && current.Status == contract.StatusCanceled {
			s.jobMu.Unlock()
			return current, nil
		}
		if s.observer != nil {
			s.observer.ObserveTranslationFailure()
		}
		if requestModeConsumesCredits(request) {
			if releaseErr := s.releaseCredits(userID, id, policy.Version); releaseErr != nil && s.observer != nil {
				s.observer.ObserveLedgerInconsistency()
			}
		}
		resource.Status = contract.StatusFailed
		providerErr := provider.NormalizeProviderError(err)
		resource.ErrorCode = providerErr.Code
		completed := s.now()
		resource.CompletedAt = &completed
		_ = s.repository.Update(resource)
		s.jobMu.Unlock()
		return nil, &RequestError{Code: providerErr.Code, Message: providerErr.Message, Retryable: providerErr.Retryable}
	}
	s.jobMu.Lock()
	if current, getErr := s.repository.Get(userID, id); getErr == nil && current.Status == contract.StatusCanceled {
		s.jobMu.Unlock()
		return current, nil
	}

	providerResult.RequestID = id
	providerResult.Usage.CreditsUsed = creditsFor(policy, providerResult.Usage.InputTokens, providerResult.Usage.OutputTokens)
	if requestModeConsumesCredits(request) {
		if providerResult.Usage.CreditsUsed <= 0 || providerResult.Usage.CreditsUsed > estimate.EstimatedCredits {
			providerResult.Usage.CreditsUsed = estimate.EstimatedCredits
			providerResult.Warnings = append(providerResult.Warnings, "provider usage was unavailable; conservative estimate was charged")
		}
		if err := s.consume(userID, id, providerResult.Usage.CreditsUsed, policy.Version); err != nil {
			if s.observer != nil {
				s.observer.ObserveLedgerInconsistency()
				s.observer.ObserveTranslationFailure()
			}
			if releaseErr := s.releaseCredits(userID, id, policy.Version); releaseErr != nil && s.observer != nil {
				s.observer.ObserveLedgerInconsistency()
			}
			resource.Status = contract.StatusFailed
			resource.ErrorCode = contract.ErrTranslationFailed
			completed := s.now()
			resource.CompletedAt = &completed
			_ = s.repository.Update(resource)
			s.jobMu.Unlock()
			return nil, &RequestError{Code: contract.ErrTranslationFailed, Message: "could not finalize credit reservation", Retryable: true}
		}
		resource.CreditsConsumed = providerResult.Usage.CreditsUsed
	}
	if s.observer != nil {
		modelCost, exists := policy.Models[providerResult.Provider.Model]
		if !exists {
			modelCost = policy.Models["default"]
		}
		s.observer.ObserveManagedUsage(providerResult.Provider.Model, providerResult.Usage.InputTokens, providerResult.Usage.OutputTokens, modelCost)
	}
	resource.Status = contract.StatusCompleted
	resource.Result = &providerResult
	completed := s.now()
	resource.CompletedAt = &completed
	if err := s.repository.Update(resource); err != nil {
		if s.observer != nil {
			s.observer.ObserveLedgerInconsistency()
		}
		s.jobMu.Unlock()
		return nil, err
	}
	if s.observer != nil {
		s.observer.ObserveTranslationSuccess()
	}
	s.jobMu.Unlock()
	return clone(resource), nil
}

func (s *Service) translateWithRetry(ctx context.Context, request provider.Request, onSegment func(contract.TranslatedSegment) error) (contract.TranslationResult, error) {
	var last error
	maxAttempts := 2
	if onSegment != nil {
		// Once a streaming callback is present, the provider may already have
		// accepted the request or emitted output when the connection fails.
		// Retrying would execute the same translation twice and could produce
		// irreconcilable partial output. The atomic path below remains retryable.
		maxAttempts = 1
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		started := time.Now()
		result, err := s.translateProvider(ctx, request, onSegment)
		if s.observer != nil {
			s.observer.ObserveProviderLatency(s.provider.Name(), time.Since(started))
		}
		if err == nil {
			return result, nil
		}
		last = err
		if !provider.NormalizeProviderError(err).Retryable || attempt+1 >= maxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return contract.TranslationResult{}, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return contract.TranslationResult{}, last
}

func (s *Service) translateProvider(ctx context.Context, request provider.Request, onSegment func(contract.TranslatedSegment) error) (contract.TranslationResult, error) {
	if streaming, ok := s.provider.(provider.StreamingProvider); ok && onSegment != nil {
		// Keep the result for each provider attempt separate. A transient stream
		// failure may happen after one or more segments have been delivered; a
		// retry must not leave those partial segments duplicated in the durable
		// result. The HTTP handler also de-duplicates already-emitted SSE IDs.
		var segments []contract.TranslatedSegment
		usage, err := streaming.TranslateStream(ctx, request, func(segment contract.TranslatedSegment) error {
			segments = append(segments, segment)
			return onSegment(segment)
		})
		result := contract.TranslationResult{Segments: segments, Usage: usage, Provider: contract.ProviderInfo{Mode: request.Mode, Name: streaming.Name(), Model: streaming.Model()}}
		return result, err
	}
	result, err := s.provider.Translate(ctx, request)
	if err == nil && onSegment != nil {
		for _, segment := range result.Segments {
			if callbackErr := onSegment(segment); callbackErr != nil {
				return contract.TranslationResult{}, callbackErr
			}
		}
	}
	return result, err
}

func (s *Service) acquire(userID string, limit int) bool {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if s.active[userID] >= limit {
		return false
	}
	s.active[userID]++
	return true
}

func (s *Service) release(userID string) {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if s.active[userID] <= 1 {
		delete(s.active, userID)
		return
	}
	s.active[userID]--
}

func (s *Service) Get(userID, id string) (*contract.TranslationResource, error) {
	return s.repository.Get(userID, id)
}

// ReconcileStale releases reservations left by a crashed process and marks
// the durable request failed. It never touches an actively running local job;
// the age threshold is deliberately longer than the managed-provider timeout.
func (s *Service) ReconcileStale(ctx context.Context, before time.Time) error {
	repository, ok := s.repository.(StaleRepository)
	if !ok {
		return nil
	}
	resources, err := repository.ListRunningBefore(ctx, before)
	if err != nil {
		return err
	}
	for _, resource := range resources {
		if err := s.reconcileStaleResource(resource); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) reconcileStaleResource(resource *contract.TranslationResource) error {
	s.jobMu.Lock()
	if _, active := s.jobs[resource.ID]; active {
		s.jobMu.Unlock()
		return nil
	}
	// Hold the job lock through release and metadata update. Cancel uses this
	// same lock, so it cannot turn a recovered request back into a competing
	// terminal state between the two operations.
	s.jobs[resource.ID] = nil
	defer func() {
		delete(s.jobs, resource.ID)
		s.jobMu.Unlock()
	}()

	if resource.CreditsReserved > resource.CreditsConsumed {
		if err := s.releaseCredits(resource.UserID, resource.ID, resource.RateVersion); err != nil {
			if s.observer != nil {
				s.observer.ObserveLedgerInconsistency()
			}
			// A process can have crashed after consuming the reservation but
			// before persisting the terminal request state. In that case there
			// is nothing left to release; mark the request failed rather than
			// leaving an idempotency key blocked forever.
			if !errors.Is(err, credits.ErrNoReservation) {
				return err
			}
		}
	}
	resource.Status = contract.StatusFailed
	resource.ErrorCode = contract.ErrProviderUnavailable
	completed := s.now()
	resource.CompletedAt = &completed
	if err := s.repository.Update(resource); err != nil {
		if s.observer != nil {
			s.observer.ObserveLedgerInconsistency()
		}
		return err
	}
	if s.observer != nil {
		s.observer.ObserveTranslationFailure()
	}
	return nil
}

func (s *Service) waitForCompletion(ctx context.Context, userID, id string) (*contract.TranslationResource, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		resource, err := s.repository.Get(userID, id)
		if err != nil {
			return nil, err
		}
		if resource.Status != contract.StatusRunning && resource.Status != contract.StatusPending {
			return resource, nil
		}
		select {
		case <-ctx.Done():
			return nil, &RequestError{Code: contract.ErrTranslationFailed, Message: "translation request canceled while waiting", Retryable: true}
		case <-ticker.C:
		}
	}
}

func (s *Service) Cancel(userID, id string) (*contract.TranslationResource, error) {
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	resource, err := s.repository.Get(userID, id)
	if err != nil {
		return nil, err
	}
	if resource.Status == contract.StatusCompleted || resource.Status == contract.StatusFailed || resource.Status == contract.StatusCanceled {
		return resource, nil
	}
	resource.Status = contract.StatusCanceled
	completed := s.now()
	resource.CompletedAt = &completed
	_ = s.releaseCredits(userID, id, resource.RateVersion)
	if err := s.repository.Update(resource); err != nil {
		return nil, err
	}
	if stop := s.jobs[id]; stop != nil {
		stop()
	}
	return resource, nil
}

func (s *Service) reserve(userID, requestID, planID string, amount int64, rateVersion string) error {
	if versioned, ok := s.ledger.(credits.VersionedStore); ok {
		return versioned.ReserveWithRateVersion(userID, requestID, planID, amount, rateVersion)
	}
	return s.ledger.Reserve(userID, requestID, planID, amount)
}

func (s *Service) consume(userID, requestID string, amount int64, rateVersion string) error {
	if versioned, ok := s.ledger.(credits.VersionedStore); ok {
		return versioned.ConsumeWithRateVersion(userID, requestID, amount, rateVersion)
	}
	return s.ledger.Consume(userID, requestID, amount)
}

func (s *Service) releaseCredits(userID, requestID, rateVersion string) error {
	if versioned, ok := s.ledger.(credits.VersionedStore); ok {
		return versioned.ReleaseWithRateVersion(userID, requestID, rateVersion)
	}
	return s.ledger.Release(userID, requestID)
}

type RequestError struct {
	Code      contract.APIErrorCode
	Message   string
	Retryable bool
	// HTTPStatus overrides the code's default status for operational states
	// that use the same public error code. In particular, a circuit-breaker
	// pause is a temporary 503, while an upstream provider failure is a 502.
	HTTPStatus int
}

func (e *RequestError) Error() string { return e.Message }

func requestModeConsumesCredits(_ contract.TranslationRequest) bool { return true }

func validationErrorCode(err error) contract.APIErrorCode {
	message := err.Error()
	if strings.Contains(message, "too large") || strings.Contains(message, "too many") {
		return contract.ErrRequestTooLarge
	}
	return contract.ErrInvalidRequest
}

func estimateUsage(request contract.TranslationRequest) (int64, int64) {
	var input int64
	for _, segment := range request.Segments {
		input += contract.EstimateTokens(segment.Text)
	}
	return input, input
}

func creditsFor(policy credits.RatePolicy, input, output int64) int64 {
	return ceilBy(input, policy.InputTokensPerCredit) + policy.OutputWeight*ceilBy(output, policy.OutputTokensPerCredit)
}

func ceilBy(tokens, unit int64) int64 {
	if tokens <= 0 || unit <= 0 {
		return 0
	}
	return (tokens + unit - 1) / unit
}

func cloneRatePolicy(policy credits.RatePolicy) credits.RatePolicy {
	policy.Models = map[string]credits.ModelCost{}
	for model, cost := range policy.Models {
		policy.Models[model] = cost
	}
	return policy
}

func idempotencyKey(userID, key string) string { return userID + "\x00" + key }

func newID(prefix string) string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(bytes[:])
}

func clone(resource *contract.TranslationResource) *contract.TranslationResource {
	copy := *resource
	if resource.Result != nil {
		result := *resource.Result
		result.Segments = append([]contract.TranslatedSegment(nil), resource.Result.Segments...)
		result.Warnings = append([]string(nil), resource.Result.Warnings...)
		copy.Result = &result
	}
	return &copy
}

func cloneMetadata(resource *contract.TranslationResource) *contract.TranslationResource {
	copy := clone(resource)
	copy.Result = nil
	return copy
}
