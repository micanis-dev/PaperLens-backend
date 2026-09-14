package contract

import "testing"

func TestValidateTranslationRequest(t *testing.T) {
	request := TranslationRequest{
		DocumentID: "paper_1", SourceLanguage: "auto", TargetLanguage: "ja", PreserveFormatting: true,
		Segments: []TranslationSegment{{ID: "seg_1", PageNumber: 1, Order: 0, Text: "hello", TextHash: "hash"}},
	}
	if err := ValidateTranslationRequest(request); err != nil {
		t.Fatal(err)
	}
	request.TargetLanguage = "xx"
	if err := ValidateTranslationRequest(request); err == nil {
		t.Fatal("unsupported language should fail")
	}
}

func TestValidateTranslationRequestRejectsDuplicateSegmentIDs(t *testing.T) {
	request := TranslationRequest{DocumentID: "paper", SourceLanguage: "auto", TargetLanguage: "ja", Segments: []TranslationSegment{{ID: "same", PageNumber: 1, Text: "one", TextHash: "h1"}, {ID: "same", PageNumber: 1, Order: 1, Text: "two", TextHash: "h2"}}}
	if err := ValidateTranslationRequest(request); err == nil {
		t.Fatal("duplicate segment IDs should fail")
	}
}
