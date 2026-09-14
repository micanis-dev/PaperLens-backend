package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type testLoginStore struct {
	oauth map[string]time.Time
	links map[string]struct {
		userID    string
		expiresAt time.Time
	}
}

func newTestLoginStore() *testLoginStore {
	return &testLoginStore{oauth: make(map[string]time.Time), links: make(map[string]struct {
		userID    string
		expiresAt time.Time
	})}
}

func (s *testLoginStore) SaveOAuthState(hash string, expiresAt time.Time) error {
	s.oauth[hash] = expiresAt
	return nil
}
func (s *testLoginStore) ConsumeOAuthState(hash string, now time.Time) (bool, error) {
	expiresAt, ok := s.oauth[hash]
	delete(s.oauth, hash)
	return ok && now.Before(expiresAt), nil
}
func (s *testLoginStore) SaveMagicLink(hash, userID string, expiresAt time.Time) error {
	s.links[hash] = struct {
		userID    string
		expiresAt time.Time
	}{userID, expiresAt}
	return nil
}
func (s *testLoginStore) ConsumeMagicLink(hash string, now time.Time) (string, bool, error) {
	entry, ok := s.links[hash]
	delete(s.links, hash)
	return entry.userID, ok && now.Before(entry.expiresAt), nil
}

func TestMagicLinkIsOneTimeAndDevelopmentCanRunWithoutSMTP(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	service := NewLoginService(LoginConfig{AppEnv: "development", MagicLinkBaseURL: "http://api.test/v1/auth/magic-link/verify"}, nil, nil, func() time.Time { return now })
	token, err := service.RequestMagicLink("Researcher@example.com")
	if err != nil || token == "" {
		t.Fatalf("request magic link: token=%q err=%v", token, err)
	}
	userID, err := service.ConsumeMagicLink(token)
	if err != nil || !strings.HasPrefix(userID, "user_email_") {
		t.Fatalf("consume magic link: user=%q err=%v", userID, err)
	}
	if _, err := service.ConsumeMagicLink(token); err != ErrExpiredLogin {
		t.Fatalf("second consume error=%v, want expired/invalid link", err)
	}
}

func TestMagicLinkRequiresDeliveryInProduction(t *testing.T) {
	service := NewLoginService(LoginConfig{AppEnv: "production", MagicLinkBaseURL: "https://api.test/v1/auth/magic-link/verify"}, nil, nil, time.Now)
	if _, err := service.RequestMagicLink("person@example.com"); err != ErrLoginNotConfigured {
		t.Fatalf("error=%v, want not configured", err)
	}
}

func TestDurableLoginStoreKeepsChallengesOneTime(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	store := newTestLoginStore()
	service := NewLoginService(LoginConfig{AppEnv: "development", GoogleClientID: "client", GoogleRedirectURL: "https://api.test/callback", MagicLinkBaseURL: "http://api.test/verify"}, nil, nil, func() time.Time { return now }).WithStore(store)
	token, err := service.RequestMagicLink("person@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.links[hashToken(token)]; !ok {
		t.Fatal("durable store did not receive a hashed magic-link challenge")
	}
	if _, err := service.ConsumeMagicLink(token); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConsumeMagicLink(token); err != ErrExpiredLogin {
		t.Fatalf("second durable consume error=%v, want expired", err)
	}
}

func TestGoogleCallbackValidatesStateAndUsesUserinfoSubject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/token" {
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "access"})
			return
		}
		if request.Header.Get("Authorization") != "Bearer access" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "google-sub", "email": "person@example.com", "email_verified": true})
	}))
	defer server.Close()
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	service := NewLoginService(LoginConfig{GoogleClientID: "client", GoogleClientSecret: "secret", GoogleRedirectURL: "https://api.test/callback", GoogleTokenURL: server.URL + "/token", GoogleUserInfoURL: server.URL + "/userinfo"}, server.Client(), nil, func() time.Time { return now })
	authorization, err := service.GoogleURL()
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(authorization)
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/callback?state="+url.QueryEscape(parsed.Query().Get("state"))+"&code=code", nil)
	userID, err := service.CompleteGoogle(request)
	if err != nil || !strings.HasPrefix(userID, "user_google_") {
		t.Fatalf("user=%q err=%v", userID, err)
	}
	if _, err := service.CompleteGoogle(request); err != ErrExpiredLogin {
		t.Fatalf("reused state error=%v, want expired", err)
	}
}
