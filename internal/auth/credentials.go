package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

const (
	ProviderApple  = "apple"
	ProviderGoogle = "google"
	ProviderGitHub = "github"
)

var (
	ErrEmailAlreadyRegistered = errors.New("email is already registered")
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrPasswordTooShort       = errors.New("password is too short")
	ErrIdentityAlreadyLinked  = errors.New("identity is already linked")
	ErrIdentityNotFound       = errors.New("identity is not found")
	ErrIdentityNotLinked      = errors.New("identity is not linked")
	ErrLastAuthMethod         = errors.New("at least one authentication method must remain")
)

const MinimumPasswordLength = 12

type PasswordCredential struct {
	UserID       string
	PasswordHash string
}

type LinkedIdentity struct {
	Provider string `json:"provider"`
}

type OAuthProfile struct {
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
}

// CredentialStore is the persistence boundary for local credentials and SSO
// identities. It deliberately exposes hashes and opaque provider subjects,
// never plaintext passwords or provider access tokens.
type CredentialStore interface {
	CreatePasswordUser(context.Context, string, string) (string, error)
	PasswordCredential(context.Context, string) (PasswordCredential, error)
	FindOAuthUser(context.Context, string, string) (string, error)
	CreateOAuthUser(context.Context, OAuthProfile, string) (string, error)
	LinkOAuthIdentity(context.Context, string, OAuthProfile, string) error
	UnlinkOAuthIdentity(context.Context, string, string) error
	ListOAuthIdentities(context.Context, string) ([]LinkedIdentity, error)
}

func HashPassword(password string) (string, error) {
	if len([]byte(password)) < MinimumPasswordLength {
		return "", ErrPasswordTooShort
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func NormalizeEmail(value string) (string, error) {
	return normalizeEmail(value)
}

func EmailHash(email string) string {
	hash := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(hash[:])
}

// StableUserID keeps OAuth identities compatible with accounts created by the
// original Google-only flow.
func StableUserID(provider, subject string) string {
	return stableUserID(provider, subject)
}

type memoryCredential struct {
	emailHash    string
	passwordHash string
}

type MemoryCredentialStore struct {
	mu         sync.Mutex
	users      map[string]memoryCredential
	emails     map[string]string
	identities map[string]string
}

func NewMemoryCredentialStore() *MemoryCredentialStore {
	return &MemoryCredentialStore{
		users: make(map[string]memoryCredential), emails: make(map[string]string), identities: make(map[string]string),
	}
}

func (s *MemoryCredentialStore) CreatePasswordUser(_ context.Context, emailHash, passwordHash string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.emails[emailHash]; exists {
		return "", ErrEmailAlreadyRegistered
	}
	userID, err := randomUserID("password")
	if err != nil {
		return "", err
	}
	s.users[userID] = memoryCredential{emailHash: emailHash, passwordHash: passwordHash}
	s.emails[emailHash] = userID
	return userID, nil
}

func (s *MemoryCredentialStore) PasswordCredential(_ context.Context, emailHash string) (PasswordCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	userID, ok := s.emails[emailHash]
	if !ok {
		return PasswordCredential{}, ErrInvalidCredentials
	}
	credential := s.users[userID]
	if credential.passwordHash == "" {
		return PasswordCredential{}, ErrInvalidCredentials
	}
	return PasswordCredential{UserID: userID, PasswordHash: credential.passwordHash}, nil
}

func (s *MemoryCredentialStore) FindOAuthUser(_ context.Context, provider, subject string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	userID, ok := s.identities[identityKey(provider, subject)]
	if !ok {
		return "", ErrIdentityNotFound
	}
	return userID, nil
}

func (s *MemoryCredentialStore) CreateOAuthUser(_ context.Context, profile OAuthProfile, emailHash string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := identityKey(profile.Provider, profile.Subject)
	if userID, exists := s.identities[key]; exists {
		return userID, nil
	}
	if existing, exists := s.emails[emailHash]; exists {
		return existing, ErrEmailAlreadyRegistered
	}
	userID := stableUserID(profile.Provider, profile.Subject)
	if _, exists := s.users[userID]; exists {
		s.identities[key] = userID
		return userID, nil
	}
	s.users[userID] = memoryCredential{emailHash: emailHash}
	s.emails[emailHash] = userID
	s.identities[key] = userID
	return userID, nil
}

func (s *MemoryCredentialStore) LinkOAuthIdentity(_ context.Context, userID string, profile OAuthProfile, emailHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.users[userID]
	if !ok {
		return ErrInvalidCredentials
	}
	if emailHash == "" || credential.emailHash != emailHash {
		return ErrInvalidCredentials
	}
	key := identityKey(profile.Provider, profile.Subject)
	if _, exists := s.identities[key]; exists {
		return ErrIdentityAlreadyLinked
	}
	for candidate, linkedUser := range s.identities {
		if linkedUser == userID && strings.HasPrefix(candidate, profile.Provider+"\x00") {
			return ErrIdentityAlreadyLinked
		}
	}
	s.identities[key] = userID
	return nil
}

func (s *MemoryCredentialStore) UnlinkOAuthIdentity(_ context.Context, userID, provider string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var key string
	for candidate, linkedUser := range s.identities {
		if linkedUser == userID && strings.HasPrefix(candidate, provider+"\x00") {
			key = candidate
			break
		}
	}
	if key == "" {
		return ErrIdentityNotLinked
	}
	credential := s.users[userID]
	count := 0
	for _, linkedUser := range s.identities {
		if linkedUser == userID {
			count++
		}
	}
	if credential.passwordHash == "" && count <= 1 {
		return ErrLastAuthMethod
	}
	delete(s.identities, key)
	return nil
}

func (s *MemoryCredentialStore) ListOAuthIdentities(_ context.Context, userID string) ([]LinkedIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := make(map[string]bool)
	var result []LinkedIdentity
	for key, linkedUser := range s.identities {
		if linkedUser != userID {
			continue
		}
		provider, _, _ := strings.Cut(key, "\x00")
		if !seen[provider] {
			result = append(result, LinkedIdentity{Provider: provider})
			seen[provider] = true
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Provider < result[j].Provider })
	return result, nil
}

func identityKey(provider, subject string) string { return provider + "\x00" + subject }

func randomUserID(provider string) (string, error) {
	token, err := randomToken(16)
	if err != nil {
		return "", err
	}
	return "user_" + provider + "_" + token, nil
}
