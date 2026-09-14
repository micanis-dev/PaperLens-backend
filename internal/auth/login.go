package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	FrontendBaseURL    string
	MagicLinkBaseURL   string
	SMTPHost           string
	SMTPPort           string
	SMTPUsername       string
	SMTPPassword       string
	SMTPFrom           string
}

type EmailSender func(to, subject, body string) error

type LoginService struct {
	config LoginConfig
	now    func() time.Time
	client *http.Client
	send   EmailSender
	store  LoginStore
	mu     sync.Mutex
	states map[string]loginState
	links  map[string]magicLink
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

type loginState struct {
	expiresAt time.Time
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
	if strings.TrimSpace(s.config.GoogleClientID) == "" || strings.TrimSpace(s.config.GoogleRedirectURL) == "" {
		return "", ErrLoginNotConfigured
	}
	state, err := randomToken(32)
	if err != nil {
		return "", err
	}
	now := s.now()
	expiresAt := now.Add(10 * time.Minute)
	if s.store != nil {
		if err := s.store.SaveOAuthState(hashToken(state), expiresAt); err != nil {
			return "", err
		}
	}
	s.mu.Lock()
	s.cleanupLocked(now)
	if s.store == nil {
		s.states[state] = loginState{expiresAt: expiresAt}
	}
	s.mu.Unlock()
	values := url.Values{}
	values.Set("client_id", s.config.GoogleClientID)
	values.Set("redirect_uri", s.config.GoogleRedirectURL)
	values.Set("response_type", "code")
	values.Set("scope", "openid email profile")
	values.Set("state", state)
	values.Set("prompt", "select_account")
	return "https://accounts.google.com/o/oauth2/v2/auth?" + values.Encode(), nil
}

func (s *LoginService) CompleteGoogle(request *http.Request) (string, error) {
	state := strings.TrimSpace(request.URL.Query().Get("state"))
	code := strings.TrimSpace(request.URL.Query().Get("code"))
	if state == "" || code == "" {
		return "", ErrInvalidLogin
	}
	now := s.now()
	ok := false
	if s.store != nil {
		var err error
		ok, err = s.store.ConsumeOAuthState(hashToken(state), now)
		if err != nil {
			return "", err
		}
	} else {
		s.mu.Lock()
		entry, found := s.states[state]
		if found {
			delete(s.states, state)
		}
		s.cleanupLocked(now)
		s.mu.Unlock()
		ok = found && now.Before(entry.expiresAt)
	}
	if !ok {
		return "", ErrExpiredLogin
	}
	tokenURL := s.config.GoogleTokenURL
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	form := url.Values{"code": {code}, "client_id": {s.config.GoogleClientID}, "client_secret": {s.config.GoogleClientSecret}, "redirect_uri": {s.config.GoogleRedirectURL}, "grant_type": {"authorization_code"}}
	tokenRequest, err := http.NewRequestWithContext(request.Context(), http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResponse, err := s.client.Do(tokenRequest)
	if err != nil {
		return "", err
	}
	defer tokenResponse.Body.Close()
	if tokenResponse.StatusCode < 200 || tokenResponse.StatusCode >= 300 {
		return "", ErrInvalidLogin
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(tokenResponse.Body, 64<<10)).Decode(&token); err != nil || token.AccessToken == "" {
		return "", ErrInvalidLogin
	}
	userInfoURL := s.config.GoogleUserInfoURL
	if userInfoURL == "" {
		userInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
	}
	userRequest, err := http.NewRequestWithContext(request.Context(), http.MethodGet, userInfoURL, nil)
	if err != nil {
		return "", err
	}
	userRequest.Header.Set("Authorization", "Bearer "+token.AccessToken)
	userResponse, err := s.client.Do(userRequest)
	if err != nil {
		return "", err
	}
	defer userResponse.Body.Close()
	if userResponse.StatusCode < 200 || userResponse.StatusCode >= 300 {
		return "", ErrInvalidLogin
	}
	var profile struct {
		Subject  string `json:"sub"`
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := json.NewDecoder(io.LimitReader(userResponse.Body, 64<<10)).Decode(&profile); err != nil || profile.Subject == "" {
		return "", ErrInvalidLogin
	}
	if profile.Email != "" && !profile.Verified {
		return "", ErrInvalidLogin
	}
	return stableUserID("google", profile.Subject), nil
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
