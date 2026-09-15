package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/micanis/paperlens/backend/internal/contract"
)

func TestOpenAICompatibleProviderMapsAndValidatesSegments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/chat/completions" || request.Header.Get("Authorization") != "Bearer key" {
			t.Fatalf("unexpected provider request: path=%s auth=%q", request.URL.Path, request.Header.Get("Authorization"))
		}
		var payload struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil || payload.Model != "selected-model" {
			t.Fatalf("selected model was not forwarded: %+v err=%v", payload, err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]string{"content": `[{"id":"b","translatedText":"B"},{"id":"a","translatedText":"A"}]`}}},
			"usage":   map[string]int{"prompt_tokens": 10, "completion_tokens": 20},
		})
	}))
	defer server.Close()
	result, err := (OpenAICompatibleProvider{BaseURL: server.URL + "/v1", APIKey: "key", ModelName: "default-model", Client: server.Client()}).Translate(context.Background(), Request{
		Mode:  contract.ModePaperLensManaged,
		Model: "selected-model",
		Segments: []contract.TranslationSegment{
			{ID: "a", PageNumber: 1, Text: "a", TextHash: "ha"},
			{ID: "b", PageNumber: 1, Text: "b", TextHash: "hb"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Segments) != 2 || result.Segments[0].ID != "a" || result.Segments[0].SourceTextHash != "ha" || result.Usage.OutputTokens != 20 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestOpenAICompatibleProviderRejectsDuplicateOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": `[{"id":"a","translatedText":"A"},{"id":"a","translatedText":"A2"}]`}}}})
	}))
	defer server.Close()
	_, err := (OpenAICompatibleProvider{BaseURL: server.URL, APIKey: "key", ModelName: "model", Client: server.Client()}).Translate(context.Background(), Request{Segments: []contract.TranslationSegment{{ID: "a", PageNumber: 1, Text: "a", TextHash: "ha"}}})
	if err == nil {
		t.Fatal("expected duplicate output to fail")
	}
}

func TestOpenAICompatibleProviderStreamsCompletedJSONSegments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if _, err := fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"[{\\\"id\\\":\\\"a\\\",\\\"translatedText\\\":\\\"A\\\"},\"}}]}\n\n"); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"{\\\"id\\\":\\\"b\\\",\\\"translatedText\\\":\\\"B\\\"}]\"}}]}\n\n"); err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprint(w, "data: {\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":22}}\n\ndata: [DONE]\n\n")
	}))
	defer server.Close()
	var got []contract.TranslatedSegment
	usage, err := (OpenAICompatibleProvider{BaseURL: server.URL, APIKey: "key", ModelName: "model", Client: server.Client()}).TranslateStream(context.Background(), Request{Segments: []contract.TranslationSegment{{ID: "a", PageNumber: 1, Text: "a", TextHash: "ha"}, {ID: "b", PageNumber: 2, Text: "b", TextHash: "hb"}}}, func(segment contract.TranslatedSegment) error { got = append(got, segment); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "a" || got[1].PageNumber != 2 || usage.OutputTokens != 22 {
		t.Fatalf("segments=%+v usage=%+v", got, usage)
	}
}

func TestOpenAICompatibleProviderRejectsDuplicateStreamSegment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"[{\\\"id\\\":\\\"a\\\",\\\"translatedText\\\":\\\"A\\\"},{\\\"id\\\":\\\"a\\\",\\\"translatedText\\\":\\\"A2\\\"}]\"}}]}\n\ndata: [DONE]\n\n")
	}))
	defer server.Close()
	_, err := (OpenAICompatibleProvider{BaseURL: server.URL, APIKey: "key", ModelName: "model", Client: server.Client()}).TranslateStream(context.Background(), Request{Segments: []contract.TranslationSegment{{ID: "a", PageNumber: 1, Text: "a", TextHash: "ha"}}}, func(contract.TranslatedSegment) error { return nil })
	if err == nil {
		t.Fatal("expected duplicate streamed segment to fail")
	}
}
