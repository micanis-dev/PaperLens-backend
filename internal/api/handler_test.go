package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/micanis/paperlens/backend/internal/account"
	"testing"

	"github.com/micanis/paperlens/backend/internal/auth"
	"github.com/micanis/paperlens/backend/internal/billing"
	"github.com/micanis/paperlens/backend/internal/config"
	"github.com/micanis/paperlens/backend/internal/credits"
	"github.com/micanis/paperlens/backend/internal/provider"
	"github.com/micanis/paperlens/backend/internal/translation"
)

type apiBillingProvider struct{}

func (apiBillingProvider) CreateCheckout(context.Context, string, string, string, string, string) (billing.CheckoutSession, error) {
	return billing.CheckoutSession{ID: "cs_test", URL: "https://checkout.test/session"}, nil
}

func (apiBillingProvider) CreatePortal(context.Context, string, string) (string, error) {
	return "https://billing.test/session", nil
}

func testHandler() http.Handler {
	ledger := credits.NewLedger(nil)
	service := translation.NewService(translation.NewMemoryRepository(), ledger, provider.EchoProvider{}, nil)
	return NewHandler(config.Config{AppEnv: "development", FrontendOrigins: []string{"http://frontend.test"}}, auth.SessionAuthenticator{DevUserID: "test-user"}, ledger, service).Routes()
}

func TestHealthIsPublicAndDoesNotExposeConfiguration(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/healthz", nil)
	testHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "DATABASE_URL") {
		t.Fatal("health exposed configuration")
	}
}

func TestMetricsRequiresAdminSession(t *testing.T) {
	ledger := credits.NewLedger(nil)
	service := translation.NewService(translation.NewMemoryRepository(), ledger, provider.EchoProvider{}, nil)
	server := NewHandler(config.Config{AppEnv: "development", SessionCookieName: "session", FrontendOrigins: []string{"http://frontend.test"}, AdminUserIDs: []string{"test-user"}}, auth.SessionAuthenticator{CookieName: "session", DevUserID: "test-user"}, ledger, service).Routes()
	request := httptest.NewRequest(http.MethodGet, "/v1/internal/metrics", nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("status=%d content-type=%q body=%s", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "paperlens_http_requests_total") {
		t.Fatal("metrics exposition missing HTTP counter")
	}

	nonAdmin := NewHandler(config.Config{AppEnv: "development", SessionCookieName: "session", FrontendOrigins: []string{"http://frontend.test"}, AdminUserIDs: []string{"other-user"}}, auth.SessionAuthenticator{CookieName: "session", DevUserID: "test-user"}, ledger, service).Routes()
	denied := httptest.NewRecorder()
	nonAdmin.ServeHTTP(denied, request)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("non-admin metrics status=%d body=%s", denied.Code, denied.Body.String())
	}
}

func TestLogoutClearsAndRevokesSession(t *testing.T) {
	revoked := auth.NewRevokedSessions()
	authenticator := auth.SessionAuthenticator{CookieName: "session", DevUserID: "test-user", Revoked: revoked}
	ledger := credits.NewLedger(nil)
	service := translation.NewService(translation.NewMemoryRepository(), ledger, provider.EchoProvider{}, nil)
	server := NewHandler(config.Config{AppEnv: "development", SessionCookieName: "session", FrontendOrigins: []string{"http://frontend.test"}}, authenticator, ledger, service).Routes()
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	request.AddCookie(&http.Cookie{Name: "session", Value: "dev-session"})
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Result().Cookies()[0].MaxAge != -1 {
		t.Fatalf("status=%d cookies=%v", recorder.Code, recorder.Result().Cookies())
	}
	check := httptest.NewRequest(http.MethodGet, "/v1/account", nil)
	check.AddCookie(&http.Cookie{Name: "session", Value: "dev-session"})
	checkRecorder := httptest.NewRecorder()
	server.ServeHTTP(checkRecorder, check)
	if checkRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session status=%d body=%s", checkRecorder.Code, checkRecorder.Body.String())
	}
}

func TestTranslationAndIdempotency(t *testing.T) {
	payload := `{"documentId":"paper_1","sourceLanguage":"en","targetLanguage":"ja","preserveFormatting":true,"segments":[{"id":"seg_1","pageNumber":1,"order":0,"text":"hello","textHash":"hash"}]}`
	server := testHandler()
	for range 2 {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/v1/translations", strings.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "012345678901234567890123456789012345")
		server.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
		}
		var envelope struct {
			Translation struct {
				ID string `json:"id"`
			} `json:"translation"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Translation.ID == "" {
			t.Fatal("missing translation id")
		}
	}
}

func TestTranslationCanBeConsumedAsSSE(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/translations", strings.NewReader(`{"documentId":"paper_1","sourceLanguage":"en","targetLanguage":"ja","preserveFormatting":true,"segments":[{"id":"seg_1","pageNumber":1,"order":0,"text":"hello","textHash":"hash"}]}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Idempotency-Key", "012345678901234567890123456789012346")
	recorder := httptest.NewRecorder()
	testHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("status=%d content-type=%q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
	body := recorder.Body.String()
	for _, event := range []string{"event: started", "event: segment", "event: usage", "event: completed"} {
		if !strings.Contains(body, event) {
			t.Fatalf("SSE missing %q: %s", event, body)
		}
	}
	if strings.Contains(body, `"translationId":""`) {
		t.Fatal("SSE started event did not include a translation ID")
	}
}

func TestAdminRatePolicyRequiresAllowlistedUserAndPublishesPolicy(t *testing.T) {
	ledger := credits.NewLedger(nil)
	service := translation.NewService(translation.NewMemoryRepository(), ledger, provider.EchoProvider{}, nil)
	server := NewHandler(config.Config{AppEnv: "development", FrontendOrigins: []string{"http://frontend.test"}, AdminUserIDs: []string{"test-user"}}, auth.SessionAuthenticator{DevUserID: "test-user"}, ledger, service).Routes()
	policy := credits.DefaultRatePolicy()
	policy.Version = "2026-10-01"
	body, _ := json.Marshal(policy)
	request := httptest.NewRequest(http.MethodPut, "/v1/admin/rates", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://frontend.test")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "2026-10-01") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestJSONBoundaryRejectsTrailingValues(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/translations", strings.NewReader(`{"documentId":"paper_1","sourceLanguage":"en","targetLanguage":"ja","preserveFormatting":true,"segments":[{"id":"seg_1","pageNumber":1,"order":0,"text":"hello","textHash":"hash"}]} {}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "012345678901234567890123456789012347")
	recorder := httptest.NewRecorder()
	testHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestJSONBoundaryReturns413ForOversizedBodies(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/translations", strings.NewReader(`"`+strings.Repeat("x", 9<<20)+`"`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "012345678901234567890123456789012348")
	recorder := httptest.NewRecorder()
	testHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestStateChangingRequestRejectsUnknownOrigin(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	request.Header.Set("Origin", "https://evil.example")
	recorder := httptest.NewRecorder()
	testHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestResponseRequestIDIsGeneratedByServer(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/v1/healthz", nil)
	request.Header.Set("X-Request-ID", "client-controlled")
	recorder := httptest.NewRecorder()
	testHandler().ServeHTTP(recorder, request)
	var response struct {
		RequestID string `json:"requestId"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.RequestID == "client-controlled" || !strings.HasPrefix(response.RequestID, "req_") {
		t.Fatalf("requestId=%q", response.RequestID)
	}
}

func TestBillingRoutesUseAuthenticatedSessionAndCommonJSONBoundary(t *testing.T) {
	ledger := credits.NewLedger(nil)
	service := translation.NewService(translation.NewMemoryRepository(), ledger, provider.EchoProvider{}, nil)
	billingService := billing.NewService(billing.NewMemoryStore(), apiBillingProvider{}, billing.Config{
		SecretKey: "sk_test", WebhookSecret: "whsec_test",
		PriceIDs: map[string]string{"plus": "price_plus", "pro": "price_pro", "ultra": "price_ultra"},
	}, nil)
	server := NewHandler(config.Config{AppEnv: "development", SessionCookieName: "session", FrontendOrigins: []string{"http://frontend.test"}}, auth.SessionAuthenticator{CookieName: "session", DevUserID: "test-user"}, ledger, service).WithBillingService(billingService).Routes()

	info := httptest.NewRecorder()
	server.ServeHTTP(info, httptest.NewRequest(http.MethodGet, "/v1/billing", nil))
	if info.Code != http.StatusOK || !strings.Contains(info.Body.String(), `"plan"`) {
		t.Fatalf("billing info status=%d body=%s", info.Code, info.Body.String())
	}

	checkout := httptest.NewRecorder()
	checkoutRequest := httptest.NewRequest(http.MethodPost, "/v1/checkout", strings.NewReader(`{"planId":"pro"}`))
	checkoutRequest.Header.Set("Content-Type", "application/json")
	server.ServeHTTP(checkout, checkoutRequest)
	if checkout.Code != http.StatusOK || !strings.Contains(checkout.Body.String(), "cs_test") {
		t.Fatalf("checkout status=%d body=%s", checkout.Code, checkout.Body.String())
	}
}

func TestAccountDeletionRequiresRecentLoginAndCanBeCanceled(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	secret := []byte("a sufficiently long test session secret")
	authenticator := auth.SessionAuthenticator{CookieName: "session", Production: true, Secret: secret, Now: func() time.Time { return now }, Revoked: auth.NewRevokedSessions()}
	ledger := credits.NewLedger(func() time.Time { return now })
	service := translation.NewService(translation.NewMemoryRepository(), ledger, provider.EchoProvider{}, func() time.Time { return now })
	server := NewHandler(config.Config{AppEnv: "production", SessionCookieName: "session", FrontendOrigins: []string{"https://frontend.test"}}, authenticator, ledger, service).WithAccountService(account.NewService(account.NewMemoryStore(), func() time.Time { return now })).Routes()
	loginResponse := httptest.NewRecorder()
	authenticator.SetSessionCookie(loginResponse, "user_1")
	cookie := loginResponse.Result().Cookies()[0]
	request := httptest.NewRequest(http.MethodPost, "/v1/account/deletion", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://frontend.test")
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "executeAt") {
		t.Fatalf("deletion status=%d body=%s", response.Code, response.Body.String())
	}
	cancel := httptest.NewRecorder()
	cancelRequest := httptest.NewRequest(http.MethodPost, "/v1/account/deletion/cancel", strings.NewReader(`{}`))
	cancelRequest.Header.Set("Content-Type", "application/json")
	cancelRequest.Header.Set("Origin", "https://frontend.test")
	cancelRequest.AddCookie(cookie)
	server.ServeHTTP(cancel, cancelRequest)
	if cancel.Code != http.StatusOK {
		t.Fatalf("cancel status=%d body=%s", cancel.Code, cancel.Body.String())
	}
}
