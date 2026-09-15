package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrLoginNotConfigured = errors.New("login provider is not configured")
	ErrInvalidLogin       = errors.New("invalid login request")
	ErrExpiredLogin       = errors.New("login request expired")
)

type LoginConfig struct {
	AppEnv             string
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string
	GoogleTokenURL     string
	GoogleUserInfoURL  string
	AppleClientID      string
	AppleClientSecret  string
	AppleRedirectURL   string
	AppleTeamID        string
	AppleKeyID         string
	ApplePrivateKey    string
	AppleAuthURL       string
	AppleTokenURL      string
	AppleJWKSURL       string
	GitHubClientID     string
	GitHubClientSecret string
	GitHubRedirectURL  string
	GitHubAuthURL      string
	GitHubTokenURL     string
	GitHubUserInfoURL  string
	GitHubEmailURL     string
	FrontendBaseURL    string
	MagicLinkBaseURL   string
	SMTPHost           string
	SMTPPort           string
	SMTPUsername       string
	SMTPPassword       string
	SMTPFrom           string
	OAuthProviders     map[string]OAuthProviderConfig
}

type EmailSender func(to, subject, body string) error

type LoginService struct {
	config      LoginConfig
	now         func() time.Time
	client      *http.Client
	send        EmailSender
	store       LoginStore
	credentials CredentialStore
	mu          sync.Mutex
	states      map[string]loginState
	links       map[string]magicLink
}

// LoginStore is the durable boundary for short-lived OAuth and magic-link
// challenges. Implementations must store only ChallengeHash values, never
// the raw browser token.
type LoginStore interface {
	SaveOAuthState(hash string, expiresAt time.Time) error
	ConsumeOAuthState(hash string, now time.Time) (bool, error)
	SaveMagicLink(hash, userID string, expiresAt time.Time) error
	ConsumeMagicLink(hash string, now time.Time) (string, bool, error)
}

func (s *LoginService) WithStore(store LoginStore) *LoginService {
	s.store = store
	return s
}

func (s *LoginService) WithCredentialStore(store CredentialStore) *LoginService {
	s.credentials = store
	return s
}

type loginState struct {
	expiresAt time.Time
	provider  string
	userID    string
}

type magicLink struct {
	userID    string
	expiresAt time.Time
}

func NewLoginService(config LoginConfig, client *http.Client, send EmailSender, now func() time.Time) *LoginService {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if now == nil {
		now = time.Now
	}
	return &LoginService{config: config, client: client, send: send, now: now, states: make(map[string]loginState), links: make(map[string]magicLink)}
}

func (s *LoginService) GoogleURL() (string, error) {
	return s.OAuthURL(ProviderGoogle, "")
}

func (s *LoginService) CompleteGoogle(request *http.Request) (string, error) {
	profile, state, err := s.CompleteOAuth(request)
	if err != nil {
		return "", err
	}
	if profile.Provider != ProviderGoogle || state.UserID != "" {
		return "", ErrInvalidLogin
	}
	return stableUserID(ProviderGoogle, profile.Subject), nil
}

func (s *LoginService) RegisterPassword(email, password string) (string, error) {
	if s.credentials == nil {
		return "", ErrLoginNotConfigured
	}
	normalized, err := NormalizeEmail(email)
	if err != nil {
		return "", ErrInvalidLogin
	}
	passwordHash, err := HashPassword(password)
	if err != nil {
		return "", err
	}
	return s.credentials.CreatePasswordUser(context.Background(), EmailHash(normalized), passwordHash)
}

func (s *LoginService) LoginPassword(email, password string) (string, error) {
	if s.credentials == nil {
		return "", ErrLoginNotConfigured
	}
	normalized, err := NormalizeEmail(email)
	if err != nil {
		return "", ErrInvalidCredentials
	}
	credential, err := s.credentials.PasswordCredential(context.Background(), EmailHash(normalized))
	if err != nil || !CheckPassword(credential.PasswordHash, password) {
		return "", ErrInvalidCredentials
	}
	return credential.UserID, nil
}

// RequestMagicLink stores only a hash of the random token. The raw token is
// returned to the caller solely for a development response or for a custom
// mail sender; it is never logged or persisted.
func (s *LoginService) RequestMagicLink(email string) (string, error) {
	normalized, err := normalizeEmail(email)
	if err != nil {
		return "", ErrInvalidLogin
	}
	if (s.send == nil && s.config.AppEnv == "production") || strings.TrimSpace(s.config.MagicLinkBaseURL) == "" {
		return "", ErrLoginNotConfigured
	}
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	userID := stableUserID("email", normalized)
	now := s.now()
	hash := hashToken(token)
	expiresAt := now.Add(15 * time.Minute)
	if s.store != nil {
		if err := s.store.SaveMagicLink(hash, userID, expiresAt); err != nil {
			return "", err
		}
	}
	s.mu.Lock()
	s.cleanupLocked(now)
	if s.store == nil {
		s.links[hash] = magicLink{userID: userID, expiresAt: expiresAt}
	}
	s.mu.Unlock()
	link := strings.TrimRight(s.config.MagicLinkBaseURL, "?") + "?token=" + url.QueryEscape(token)
	if s.send != nil {
		if err := s.send(normalized, "PaperLensのログインリンク", "PaperLensへログインするには、次のリンクを開いてください。\n\n"+link+"\n\nこのリンクは15分間、一度だけ有効です。"); err != nil {
			if s.store == nil {
				s.mu.Lock()
				delete(s.links, hash)
				s.mu.Unlock()
			}
			return "", err
		}
	}
	return token, nil
}

func (s *LoginService) ConsumeMagicLink(token string) (string, error) {
	if strings.TrimSpace(token) == "" {
		return "", ErrInvalidLogin
	}
	now := s.now()
	hash := hashToken(token)
	if s.store != nil {
		userID, ok, err := s.store.ConsumeMagicLink(hash, now)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", ErrExpiredLogin
		}
		return userID, nil
	}
	s.mu.Lock()
	entry, ok := s.links[hash]
	if ok {
		delete(s.links, hash)
	}
	s.cleanupLocked(now)
	s.mu.Unlock()
	if !ok || !now.Before(entry.expiresAt) {
		return "", ErrExpiredLogin
	}
	return entry.userID, nil
}

func (s *LoginService) FrontendBaseURL() string {
	return strings.TrimRight(s.config.FrontendBaseURL, "/")
}

func (s *LoginService) cleanupLocked(now time.Time) {
	for state, entry := range s.states {
		if !now.Before(entry.expiresAt) {
			delete(s.states, state)
		}
	}
	for token, entry := range s.links {
		if !now.Before(entry.expiresAt) {
			delete(s.links, token)
		}
	}
}

func SMTPEmailSender(config LoginConfig) EmailSender {
	return func(to, subject, body string) error {
		if config.SMTPHost == "" || config.SMTPFrom == "" {
			return ErrLoginNotConfigured
		}
		port := config.SMTPPort
		if port == "" {
			port = "587"
		}
		address := config.SMTPHost + ":" + port
		var auth smtp.Auth
		if config.SMTPUsername != "" {
			auth = smtp.PlainAuth("", config.SMTPUsername, config.SMTPPassword, config.SMTPHost)
		}
		message := []byte("To: " + to + "\r\nFrom: " + config.SMTPFrom + "\r\nSubject: " + subject + "\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body + "\r\n")
		return smtp.SendMail(address, auth, config.SMTPFrom, []string{to}, message)
	}
}

func (a SessionAuthenticator) SetSessionCookie(w http.ResponseWriter, userID string) error {
	if strings.TrimSpace(userID) == "" || len(a.Secret) == 0 {
		return ErrLoginNotConfigured
	}
	now := time.Now().UTC()
	if a.Now != nil {
		now = a.Now()
	}
	http.SetCookie(w, &http.Cookie{Name: a.CookieName, Value: SessionValueWithAuthentication(userID, now.Add(SessionTTL), now, now, a.Secret), Path: "/", HttpOnly: true, Secure: a.Production, SameSite: http.SameSiteLaxMode, MaxAge: int(SessionTTL / time.Second)})
	return nil
}

// RefreshSessionCookie advances the signed activity timestamp while retaining
// the original absolute expiry. It is called after an authenticated request,
// so active users do not get re-authenticated while the seven-day idle policy
// still applies to abandoned sessions.
func (a SessionAuthenticator) RefreshSessionCookie(w http.ResponseWriter, request *http.Request) {
	if !a.Production {
		return
	}
	cookie, err := request.Cookie(a.CookieName)
	if err != nil {
		return
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 4 && len(parts) != 5 {
		return
	}
	expiresUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	if a.Now != nil {
		now = a.Now().UTC()
	}
	expiresAt := time.Unix(expiresUnix, 0).UTC()
	if !now.Before(expiresAt) {
		return
	}
	userBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(userBytes) == 0 {
		return
	}
	maxAge := int(time.Until(expiresAt) / time.Second)
	if a.Now != nil {
		maxAge = int(expiresAt.Sub(now) / time.Second)
	}
	if maxAge < 1 {
		return
	}
	value := SessionValueWithActivity(string(userBytes), expiresAt, now, a.Secret)
	if len(parts) == 5 {
		if authenticatedAt, parseErr := strconv.ParseInt(parts[3], 10, 64); parseErr == nil {
			value = SessionValueWithAuthentication(string(userBytes), expiresAt, now, time.Unix(authenticatedAt, 0).UTC(), a.Secret)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: a.CookieName, Value: value, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

// RecentlyAuthenticated reports whether the session was issued by a full
// login within the supplied window. It fails closed for legacy/raw cookies.
func (a SessionAuthenticator) RecentlyAuthenticated(request *http.Request, window time.Duration) bool {
	if window <= 0 {
		return false
	}
	cookie, err := request.Cookie(a.CookieName)
	if err != nil || cookie.Value == "" || len(a.Secret) == 0 {
		return false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 5 {
		return false
	}
	if _, ok := a.verify(cookie.Value); !ok {
		return false
	}
	authenticatedAt, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return false
	}
	now := time.Now().UTC()
	if a.Now != nil {
		now = a.Now().UTC()
	}
	issued := time.Unix(authenticatedAt, 0)
	return !now.Before(issued) && now.Sub(issued) <= window
}

func normalizeEmail(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value || !strings.Contains(value, "@") || len(value) > 320 {
		return "", ErrInvalidLogin
	}
	return value, nil
}

func stableUserID(provider, subject string) string {
	hash := sha256.Sum256([]byte(provider + "\x00" + subject))
	return "user_" + provider + "_" + hex.EncodeToString(hash[:16])
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func randomToken(size int) (string, error) {
	if size < 16 {
		size = 16
	}
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate login token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}
