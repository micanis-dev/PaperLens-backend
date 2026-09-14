package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

var supportedLanguages = map[string]struct{}{
	"ja": {}, "en": {}, "zh-CN": {}, "zh-TW": {}, "ko": {},
	"de": {}, "fr": {}, "es": {},
}

func ValidateTranslationRequest(request TranslationRequest) error {
	if strings.TrimSpace(request.DocumentID) == "" {
		return fmt.Errorf("documentId is required")
	}
	if request.SourceLanguage != "auto" && !isLanguage(request.SourceLanguage) {
		return fmt.Errorf("unsupported sourceLanguage")
	}
	if !isLanguage(request.TargetLanguage) {
		return fmt.Errorf("unsupported targetLanguage")
	}
	if len(request.Segments) == 0 {
		return fmt.Errorf("at least one segment is required")
	}
	if len(request.Segments) > 2000 {
		return fmt.Errorf("too many segments")
	}

	pages := map[int]struct{}{}
	segmentIDs := make(map[string]struct{}, len(request.Segments))
	totalChars := 0
	for index, segment := range request.Segments {
		if strings.TrimSpace(segment.ID) == "" || len(segment.ID) > 256 {
			return fmt.Errorf("segments[%d].id is required", index)
		}
		if _, exists := segmentIDs[segment.ID]; exists {
			return fmt.Errorf("segments[%d].id is duplicated", index)
		}
		segmentIDs[segment.ID] = struct{}{}
		if segment.PageNumber < 1 {
			return fmt.Errorf("segments[%d].pageNumber must be positive", index)
		}
		if segment.Order < 0 {
			return fmt.Errorf("segments[%d].order must not be negative", index)
		}
		if strings.TrimSpace(segment.Text) == "" {
			return fmt.Errorf("segments[%d].text is required", index)
		}
		if len(segment.Text) > 100_000 {
			return fmt.Errorf("segments[%d].text is too large", index)
		}
		if segment.TextHash == "" {
			return fmt.Errorf("segments[%d].textHash is required", index)
		}
		pages[segment.PageNumber] = struct{}{}
		totalChars += len(segment.Text)
	}
	if len(pages) > 500 {
		return fmt.Errorf("too many pages in one request")
	}
	if len(request.Glossary) > 200 {
		return fmt.Errorf("too many glossary entries")
	}
	for index, entry := range request.Glossary {
		if strings.TrimSpace(entry.Source) == "" || strings.TrimSpace(entry.Translation) == "" || len(entry.Source) > 2_000 || len(entry.Translation) > 2_000 {
			return fmt.Errorf("glossary[%d] is invalid", index)
		}
	}
	if totalChars > 500_000 {
		return fmt.Errorf("request text is too large")
	}
	return nil
}

func IsSupportedLanguage(language string) bool {
	return isLanguage(language)
}

func isLanguage(language string) bool {
	_, ok := supportedLanguages[language]
	return ok
}

func HashRequest(request TranslationRequest) string {
	hash := sha256.New()
	fmt.Fprintf(hash, "%s\x00%s\x00%s\x00%t\x00", request.DocumentID, request.SourceLanguage, request.TargetLanguage, request.PreserveFormatting)
	for _, segment := range request.Segments {
		fmt.Fprintf(hash, "%s\x00%d\x00%d\x00%s\x00%s\x00", segment.ID, segment.PageNumber, segment.Order, segment.Text, segment.TextHash)
	}
	for _, entry := range request.Glossary {
		fmt.Fprintf(hash, "%s\x00%s\x00", entry.Source, entry.Translation)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func EstimateTokens(text string) int64 {
	// A conservative character estimate is used before a provider returns
	// measured token usage. The final charge never replaces an estimate with a
	// smaller value after a provider omitted usage data.
	return int64((len([]rune(text)) + 3) / 4)
}
