package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/micanis/paperlens/backend/internal/contract"
)

var ErrUnavailable = errors.New("translation provider unavailable")

type Error struct {
	Code      contract.APIErrorCode
	Message   string
	Retryable bool
	Cause     error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *Error) Unwrap() error { return e.Cause }

type Request struct {
	// RequestID is stable across provider retries. Adapters can forward it as
	// their provider-specific idempotency key when the upstream supports one.
	RequestID          string
	Mode               contract.TranslationMode
	Model              string
	SourceLanguage     string
	TargetLanguage     string
	Segments           []contract.TranslationSegment
	Glossary           []contract.GlossaryEntry
	PreserveFormatting bool
}

type Provider interface {
	Translate(context.Context, Request) (contract.TranslationResult, error)
	Name() string
	Model() string
}

// StreamingProvider is optional so adapters that cannot guarantee structured
// incremental output can continue to use the atomic Translate contract.
type StreamingProvider interface {
	Provider
	TranslateStream(context.Context, Request, func(contract.TranslatedSegment) error) (contract.Usage, error)
}

// EchoProvider keeps local development deterministic and makes it possible to
// exercise reservation/idempotency paths without sending paper text anywhere.
// It is never selected automatically in production.
type EchoProvider struct {
	ProviderName  string
	ProviderModel string
}

func (p EchoProvider) Name() string {
	if p.ProviderName == "" {
		return "development-echo"
	}
	return p.ProviderName
}

func (p EchoProvider) Model() string {
	if p.ProviderModel == "" {
		return "echo"
	}
	return p.ProviderModel
}

func (p EchoProvider) Translate(_ context.Context, request Request) (contract.TranslationResult, error) {
	if len(request.Segments) == 0 {
		return contract.TranslationResult{}, &Error{Code: contract.ErrInvalidRequest, Message: "no translation segments", Retryable: false}
	}
	result := contract.TranslationResult{
		Segments: make([]contract.TranslatedSegment, 0, len(request.Segments)),
		Provider: contract.ProviderInfo{Mode: request.Mode, Name: p.Name(), Model: p.Model()},
		Warnings: []string{"development provider used; no external LLM was contacted"},
	}
	for _, segment := range request.Segments {
		result.Segments = append(result.Segments, contract.TranslatedSegment{
			ID: segment.ID, PageNumber: segment.PageNumber, TranslatedText: segment.Text, SourceTextHash: segment.TextHash,
		})
		result.Usage.InputTokens += contract.EstimateTokens(segment.Text)
		result.Usage.OutputTokens += contract.EstimateTokens(segment.Text)
	}
	return result, nil
}

func (p EchoProvider) TranslateStream(ctx context.Context, request Request, onSegment func(contract.TranslatedSegment) error) (contract.Usage, error) {
	if len(request.Segments) == 0 {
		return contract.Usage{}, &Error{Code: contract.ErrInvalidRequest, Message: "no translation segments", Retryable: false}
	}
	var usage contract.Usage
	for _, segment := range request.Segments {
		translated := contract.TranslatedSegment{ID: segment.ID, PageNumber: segment.PageNumber, TranslatedText: segment.Text, SourceTextHash: segment.TextHash}
		if err := onSegment(translated); err != nil {
			return contract.Usage{}, err
		}
		usage.InputTokens += contract.EstimateTokens(segment.Text)
		usage.OutputTokens += contract.EstimateTokens(segment.Text)
	}
	return usage, nil
}

// UnconfiguredProvider is used in production until a managed provider adapter
// is configured. It fails closed so the API never silently falls back to a
// provider or sends paper text to an unknown endpoint.
type UnconfiguredProvider struct{}

func (UnconfiguredProvider) Name() string  { return "paperlens-managed" }
func (UnconfiguredProvider) Model() string { return "" }
func (UnconfiguredProvider) Translate(context.Context, Request) (contract.TranslationResult, error) {
	return contract.TranslationResult{}, &Error{Code: contract.ErrProviderUnavailable, Message: "managed translation provider is not configured", Retryable: true, Cause: ErrUnavailable}
}

func NormalizeProviderError(err error) *Error {
	var providerErr *Error
	if errors.As(err, &providerErr) {
		return providerErr
	}
	return &Error{Code: contract.ErrTranslationFailed, Message: strings.TrimSpace(err.Error()), Retryable: false, Cause: err}
}
