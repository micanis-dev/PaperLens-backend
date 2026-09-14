package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProductionSessionIsSignedAndExpires(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	secret := []byte("a-session-secret-that-is-long-enough")
	value := SessionValue("user_1", now.Add(time.Hour), secret)
	request, _ := http.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: "session", Value: value})
	authenticator := SessionAuthenticator{CookieName: "session", Production: true, Secret: secret, Now: func() time.Time { return now }}
	identity, ok := authenticator.Authenticate(request)
	if !ok || identity.UserID != "user_1" {
		t.Fatalf("identity=%+v authenticated=%v", identity, ok)
	}
	tampered, _ := http.NewRequest(http.MethodGet, "/", nil)
	tampered.AddCookie(&http.Cookie{Name: "session", Value: value + "x"})
	if _, ok := authenticator.Authenticate(tampered); ok {
		t.Fatal("tampered session was accepted")
	}
	authenticator.Now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, ok := authenticator.Authenticate(request); ok {
		t.Fatal("expired session was accepted")
	}
}

func TestLogoutRevokesSignedSessionBeforeCookieExpiry(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	secret := []byte("a-session-secret-that-is-long-enough")
	value := SessionValue("user_1", now.Add(24*time.Hour), secret)
	request, _ := http.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	request.AddCookie(&http.Cookie{Name: "session", Value: value})
	revoked := NewRevokedSessions()
	authenticator := SessionAuthenticator{CookieName: "session", Production: true, Secret: secret, Now: func() time.Time { return now }, Revoked: revoked}
	if _, ok := authenticator.Authenticate(request); !ok {
		t.Fatal("valid session was rejected before logout")
	}
	authenticator.Revoke(request)
	if _, ok := authenticator.Authenticate(request); ok {
		t.Fatal("revoked session was accepted")
	}
}

func TestSessionRejectsSevenDayIdleButRefreshKeepsAbsoluteExpiry(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	secret := []byte("a-session-secret-that-is-long-enough")
	value := SessionValueWithActivity("user_1", now.Add(30*24*time.Hour), now, secret)
	authenticator := SessionAuthenticator{CookieName: "session", Production: true, Secret: secret, Now: func() time.Time { return now }}
	request := httptest.NewRequest(http.MethodGet, "/v1/account", nil)
	request.AddCookie(&http.Cookie{Name: "session", Value: value})
	if _, ok := authenticator.Authenticate(request); !ok {
		t.Fatal("active session was rejected")
	}
	recorder := httptest.NewRecorder()
	authenticator.RefreshSessionCookie(recorder, request)
	refreshed := recorder.Result().Cookies()
	if len(refreshed) != 1 || refreshed[0].MaxAge != int((30*24*time.Hour)/time.Second) {
		t.Fatalf("refreshed cookie=%v", refreshed)
	}
	authenticator.Now = func() time.Time { return now.Add(SessionIdleTimeout + time.Minute) }
	idleRequest := httptest.NewRequest(http.MethodGet, "/v1/account", nil)
	idleRequest.AddCookie(&http.Cookie{Name: "session", Value: value})
	if _, ok := authenticator.Authenticate(idleRequest); ok {
		t.Fatal("idle session was accepted")
	}
}
