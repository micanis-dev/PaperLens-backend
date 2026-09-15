package contract

import "time"

type TranslationMode string

const (
	ModePaperLensManaged TranslationMode = "paperlens-managed"
	ModeOpenAI           TranslationMode = "openai"
	ModeGoogle           TranslationMode = "google"
	ModeAnthropic        TranslationMode = "anthropic"
	ModeOpenAICompatible TranslationMode = "openai-compatible"
	ModeLocal            TranslationMode = "local"
)

func (m TranslationMode) ConsumesCredits() bool {
	return m == ModePaperLensManaged
}

type TranslationSegment struct {
	ID         string `json:"id"`
	PageNumber int    `json:"pageNumber"`
	Order      int    `json:"order"`
	Text       string `json:"text"`
	TextHash   string `json:"textHash"`
}

type GlossaryEntry struct {
	Source      string `json:"source"`
	Translation string `json:"translation"`
}

type TranslationRequest struct {
	DocumentID     string `json:"documentId"`
	SourceLanguage string `json:"sourceLanguage"`
	TargetLanguage string `json:"targetLanguage"`
	// Model is required for PaperLens-managed translations and is ignored for
	// direct BYOK/local flows. Keeping it in the shared request lets the server
	// select both the provider model and its credit rate atomically.
	Model              string               `json:"model,omitempty"`
	Segments           []TranslationSegment `json:"segments"`
	Glossary           []GlossaryEntry      `json:"glossary,omitempty"`
	PreserveFormatting bool                 `json:"preserveFormatting"`
}

type TranslationResult struct {
	RequestID string              `json:"requestId"`
	Segments  []TranslatedSegment `json:"segments"`
	Usage     Usage               `json:"usage"`
	Provider  ProviderInfo        `json:"provider"`
	Warnings  []string            `json:"warnings"`
}

type TranslatedSegment struct {
	ID             string `json:"id"`
	PageNumber     int    `json:"pageNumber"`
	Sequence       int    `json:"sequence,omitempty"`
	TranslatedText string `json:"translatedText"`
	SourceTextHash string `json:"sourceTextHash"`
}

type Usage struct {
	InputTokens  int64 `json:"inputTokens,omitempty"`
	OutputTokens int64 `json:"outputTokens,omitempty"`
	CreditsUsed  int64 `json:"creditsUsed"`
}

type ProviderInfo struct {
	Mode  TranslationMode `json:"mode"`
	Name  string          `json:"name"`
	Model string          `json:"model"`
}

type APIErrorCode string

const (
	ErrUnauthorized        APIErrorCode = "unauthorized"
	ErrForbidden           APIErrorCode = "forbidden"
	ErrInsufficientCredits APIErrorCode = "insufficient_credits"
	ErrRateLimited         APIErrorCode = "rate_limited"
	ErrRequestTooLarge     APIErrorCode = "request_too_large"
	ErrProviderUnavailable APIErrorCode = "provider_unavailable"
	ErrTranslationFailed   APIErrorCode = "translation_failed"
	ErrIdempotencyConflict APIErrorCode = "idempotency_conflict"
	ErrInvalidRequest      APIErrorCode = "invalid_request"
)

type APIError struct {
	Code      APIErrorCode `json:"code"`
	Message   string       `json:"message"`
	RequestID string       `json:"requestId"`
	Retryable bool         `json:"retryable"`
}

type Plan struct {
	ID              string `json:"id"`
	MonthlyPriceYen int64  `json:"monthlyPriceYen"`
	PriceVersion    string `json:"priceVersion"`
	MonthlyCredits  int64  `json:"monthlyCredits"`
	DailyCredits    int64  `json:"dailyCredits"`
	PerRequestLimit int64  `json:"perRequestLimit"`
	ConcurrentLimit int    `json:"concurrentLimit"`
	Priority        string `json:"priority"`
}

type Account struct {
	UserID            string     `json:"userId"`
	Plan              Plan       `json:"plan"`
	Subscription      string     `json:"subscriptionStatus"`
	CurrentPeriodEnd  *time.Time `json:"currentPeriodEnd,omitempty"`
	GraceUntil        *time.Time `json:"graceUntil,omitempty"`
	CancelAtPeriodEnd bool       `json:"cancelAtPeriodEnd"`
	BillingConfigured bool       `json:"billingConfigured"`
}

type CreditBalance struct {
	PlanID      string    `json:"planId"`
	Available   int64     `json:"available"`
	Reserved    int64     `json:"reserved"`
	ExpiresAt   time.Time `json:"expiresAt"`
	RateVersion string    `json:"rateVersion"`
}

type TranslationStatus string

const (
	StatusPending   TranslationStatus = "pending"
	StatusRunning   TranslationStatus = "running"
	StatusCompleted TranslationStatus = "completed"
	StatusFailed    TranslationStatus = "failed"
	StatusCanceled  TranslationStatus = "canceled"
)

type TranslationResource struct {
	ID             string             `json:"id"`
	UserID         string             `json:"-"`
	IdempotencyKey string             `json:"-"`
	RequestHash    string             `json:"-"`
	Mode           TranslationMode    `json:"mode"`
	Model          string             `json:"model"`
	RateVersion    string             `json:"rateVersion,omitempty"`
	Status         TranslationStatus  `json:"status"`
	Result         *TranslationResult `json:"result,omitempty"`
	ErrorCode      APIErrorCode       `json:"errorCode,omitempty"`
	CreatedAt      time.Time          `json:"createdAt"`
	CompletedAt    *time.Time         `json:"completedAt,omitempty"`
	// Server metadata is persisted for idempotency and accounting. Request and
	// response text are intentionally not part of this durable surface.
	SourceLanguage  string `json:"-"`
	TargetLanguage  string `json:"-"`
	SegmentCount    int    `json:"-"`
	CreditsReserved int64  `json:"-"`
	CreditsConsumed int64  `json:"-"`
}
