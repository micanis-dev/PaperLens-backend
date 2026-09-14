package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Identity struct {
	UserID        string
	Authenticated bool
}

type contextKey struct{}

func WithIdentity(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, identity)
}

func IdentityFromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(contextKey{}).(Identity)
	return identity, ok && identity.UserID != ""
}

// Authenticator is intentionally abstract. The production implementation can
// validate the HttpOnly session cookie issued by the Go API, while tests and
// local development can provide a deterministic identity without changing the
// handlers or the translation service.
type Authenticator interface {
	Authenticate(*http.Request) (Identity, bool)
}

type SessionAuthenticator struct {
	CookieName string
	DevUserID  string
	Production bool
	Secret     []byte
	Now        func() time.Time
	Revoked    SessionRevocationStore
}

type SessionRevocationStore interface {
	Revoke(value string, until time.Time)
	IsRevoked(value string, now time.Time) bool
}

const (
	SessionTTL         = 30 * 24 * time.Hour
	SessionIdleTimeout = 7 * 24 * time.Hour
)

// RevokedSessions is the server-side invalidation boundary for logout. A
// durable deployment can replace this store with PostgreSQL or Redis without
// changing the cookie or HTTP contract.
type RevokedSessions struct {
	mu    sync.RWMutex
	items map[string]time.Time
}

func NewRevokedSessions() *RevokedSessions {
	return &RevokedSessions{items: make(map[string]time.Time)}
}

func (s *RevokedSessions) Revoke(value string, until time.Time) {
	if s == nil || value == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items == nil {
		s.items = make(map[string]time.Time)
	}
	s.items[value] = until
}

func (s *RevokedSessions) IsRevoked(value string, now time.Time) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.items[value]
	if ok && now.After(until) {
		delete(s.items, value)
		return false
	}
	return ok
}

func (a SessionAuthenticator) Authenticate(request *http.Request) (Identity, bool) {
	if cookie, err := request.Cookie(a.CookieName); err == nil && cookie.Value != "" {
		now := time.Now()
		if a.Now != nil {
			now = a.Now()
		}
		if a.Revoked != nil && a.Revoked.IsRevoked(cookie.Value, now) {
			return Identity{}, false
		}
		if a.Production {
			if userID, ok := a.verify(cookie.Value); ok {
				return Identity{UserID: userID, Authenticated: true}, true
			}
			return Identity{}, false
		}
		// Development keeps the deterministic raw-cookie escape hatch used by
		// local tests, but accepts the same signed cookie issued by OAuth and
		// magic-link login when a development secret is configured.
		if len(a.Secret) > 0 {
			if userID, ok := a.verify(cookie.Value); ok {
				return Identity{UserID: userID, Authenticated: true}, true
			}
		}
		return Identity{UserID: cookie.Value, Authenticated: true}, true
	}
	if !a.Production && a.DevUserID != "" {
		return Identity{UserID: a.DevUserID, Authenticated: true}, true
	}
	return Identity{}, false
}

func (a SessionAuthenticator) Revoke(request *http.Request) {
	cookie, err := request.Cookie(a.CookieName)
	if err != nil || cookie.Value == "" || a.Revoked == nil {
		return
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	a.Revoked.Revoke(cookie.Value, now.Add(SessionTTL))
}

// SessionValue creates the value expected in the HttpOnly session cookie. The
// OAuth or magic-link boundary can issue this value without exposing a bearer
// token to the frontend. Format: base64url(userID).expiryUnix.signature.
func SessionValue(userID string, expiresAt time.Time, secret []byte) string {
	encodedUser := base64.RawURLEncoding.EncodeToString([]byte(userID))
	payload := encodedUser + "." + strconv.FormatInt(expiresAt.Unix(), 10)
	return payload + "." + sign(payload, secret)
}

// SessionValueWithActivity is the current cookie format. The last activity
// timestamp is signed so the API can enforce the seven-day inactivity window
// without placing a bearer token in browser storage. SessionValue remains
// available for compatibility with already-issued test/development cookies.
func SessionValueWithActivity(userID string, expiresAt, lastActivity time.Time, secret []byte) string {
	encodedUser := base64.RawURLEncoding.EncodeToString([]byte(userID))
	payload := encodedUser + "." + strconv.FormatInt(expiresAt.Unix(), 10) + "." + strconv.FormatInt(lastActivity.Unix(), 10)
	return payload + "." + sign(payload, secret)
}

// SessionValueWithAuthentication records the time of the last full OAuth or
// magic-link authentication separately from idle activity. This lets
// destructive account actions require a genuinely recent re-authentication.
func SessionValueWithAuthentication(userID string, expiresAt, lastActivity, authenticatedAt time.Time, secret []byte) string {
	encodedUser := base64.RawURLEncoding.EncodeToString([]byte(userID))
	payload := encodedUser + "." + strconv.FormatInt(expiresAt.Unix(), 10) + "." + strconv.FormatInt(lastActivity.Unix(), 10) + "." + strconv.FormatInt(authenticatedAt.Unix(), 10)
	return payload + "." + sign(payload, secret)
}

func (a SessionAuthenticator) verify(value string) (string, bool) {
	parts := strings.Split(value, ".")
	if (len(parts) != 3 && len(parts) != 4 && len(parts) != 5) || len(a.Secret) == 0 {
		return "", false
	}
	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", false
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	current := now()
	if expires <= current.Unix() {
		return "", false
	}
	if len(parts) == 4 || len(parts) == 5 {
		lastActivity, parseErr := strconv.ParseInt(parts[2], 10, 64)
		if parseErr != nil || lastActivity > current.Unix() || current.Sub(time.Unix(lastActivity, 0)) > SessionIdleTimeout {
			return "", false
		}
		payload := parts[0] + "." + parts[1] + "." + parts[2]
		if len(parts) == 5 {
			authenticatedAt, authErr := strconv.ParseInt(parts[3], 10, 64)
			if authErr != nil || authenticatedAt > current.Unix() || current.Sub(time.Unix(authenticatedAt, 0)) > SessionTTL {
				return "", false
			}
			payload += "." + parts[3]
		}
		if !hmac.Equal([]byte(parts[len(parts)-1]), []byte(sign(payload, a.Secret))) {
			return "", false
		}
	} else if !hmac.Equal([]byte(parts[2]), []byte(sign(parts[0]+"."+parts[1], a.Secret))) {
		return "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	return string(decoded), err == nil && len(decoded) > 0
}

func sign(payload string, secret []byte) string {
	hash := hmac.New(sha256.New, secret)
	_, _ = hash.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func revocationKey(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}
