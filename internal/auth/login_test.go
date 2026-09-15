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

func TestPasswordCredentialCanRegisterLoginAndManageSSO(t *testing.T) {
	store := NewMemoryCredentialStore()
	service := NewLoginService(LoginConfig{AppEnv: "development"}, nil, nil, time.Now).WithCredentialStore(store)
	userID, err := service.RegisterPassword("person@example.com", "a-strong-password")
	if err != nil || userID == "" {
		t.Fatalf("register user=%q err=%v", userID, err)
	}
	if _, err := service.RegisterPassword("PERSON@example.com", "another-strong-password"); err != ErrEmailAlreadyRegistered {
		t.Fatalf("duplicate registration err=%v", err)
	}
	if loggedIn, err := service.LoginPassword("PERSON@example.com", "a-strong-password"); err != nil || loggedIn != userID {
		t.Fatalf("login user=%q err=%v", loggedIn, err)
	}
	profile := OAuthProfile{Provider: ProviderGoogle, Subject: "google-sub", Email: "person@example.com", EmailVerified: true}
	if err := service.LinkOAuth(context.Background(), userID, profile); err != nil {
		t.Fatal(err)
	}
	identities, err := service.ListOAuthIdentities(context.Background(), userID)
	if err != nil || len(identities) != 1 || identities[0].Provider != ProviderGoogle {
		t.Fatalf("identities=%+v err=%v", identities, err)
	}
	if err := service.LinkOAuth(context.Background(), userID, OAuthProfile{Provider: ProviderGoogle, Subject: "another-google-sub", Email: "person@example.com", EmailVerified: true}); err != ErrIdentityAlreadyLinked {
		t.Fatalf("duplicate provider link error=%v", err)
	}
	if err := service.UnlinkOAuth(context.Background(), userID, ProviderGoogle); err != nil {
		t.Fatal(err)
	}
}

func TestOAuthURLsSupportAllConfiguredProviders(t *testing.T) {
	service := NewLoginService(LoginConfig{
		GoogleClientID: "google", GoogleRedirectURL: "https://api.test/v1/auth/google/callback",
		AppleClientID: "apple", AppleRedirectURL: "https://api.test/v1/auth/apple/callback",
		GitHubClientID: "github", GitHubRedirectURL: "https://api.test/v1/auth/github/callback",
	}, nil, nil, time.Now)
	for _, provider := range []string{ProviderApple, ProviderGoogle, ProviderGitHub} {
		location, err := service.OAuthURL(provider, "")
		if err != nil || !strings.Contains(location, "client_id=") || !strings.Contains(location, "state=") {
			t.Fatalf("provider=%s location=%q err=%v", provider, location, err)
		}
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
