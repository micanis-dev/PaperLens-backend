package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	EmailURL     string
	JWKSURL      string
}

type OAuthState struct {
	Provider string
	UserID   string
}

// OAuthStateBindingStore persists the provider and the optional account being
// linked along with the one-time state. The older LoginStore methods remain
// supported for compatibility with lightweight tests.
type OAuthStateBindingStore interface {
	SaveOAuthStateBinding(string, OAuthState, time.Time) error
	ConsumeOAuthStateBinding(string, time.Time) (OAuthState, bool, error)
}

func (s *LoginService) OAuthURL(provider, linkUserID string) (string, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	config, ok := s.oauthProvider(provider)
	if !ok || strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.RedirectURL) == "" {
		return "", ErrLoginNotConfigured
	}
	state, err := randomToken(32)
	if err != nil {
		return "", err
	}
	now := s.now()
	expiresAt := now.Add(10 * time.Minute)
	binding := OAuthState{Provider: provider, UserID: strings.TrimSpace(linkUserID)}
	if durable, ok := s.store.(OAuthStateBindingStore); ok {
		if err := durable.SaveOAuthStateBinding(hashToken(state), binding, expiresAt); err != nil {
			return "", err
		}
	} else {
		if s.store != nil {
			if err := s.store.SaveOAuthState(hashToken(state), expiresAt); err != nil {
				return "", err
			}
		}
		s.mu.Lock()
		s.cleanupLocked(now)
		s.states[state] = loginState{expiresAt: expiresAt, provider: provider, userID: binding.UserID}
		s.mu.Unlock()
	}
	authURL := config.AuthURL
	if authURL == "" {
		switch provider {
		case ProviderGoogle:
			authURL = "https://accounts.google.com/o/oauth2/v2/auth"
		case ProviderGitHub:
			authURL = "https://github.com/login/oauth/authorize"
		case ProviderApple:
			authURL = "https://appleid.apple.com/auth/authorize"
		}
	}
	scope := "openid email profile"
	if provider == ProviderGitHub {
		scope = "read:user user:email"
	}
	values := url.Values{
		"client_id": {config.ClientID}, "redirect_uri": {config.RedirectURL},
		"response_type": {"code"}, "scope": {scope}, "state": {state},
	}
	if provider == ProviderGoogle {
		values.Set("prompt", "select_account")
	}
	if provider == ProviderApple {
		values.Set("response_mode", "query")
	}
	return authURL + "?" + values.Encode(), nil
}

func (s *LoginService) CompleteOAuth(request *http.Request) (OAuthProfile, OAuthState, error) {
	stateToken := strings.TrimSpace(request.URL.Query().Get("state"))
	code := strings.TrimSpace(request.URL.Query().Get("code"))
	if stateToken == "" || code == "" {
		return OAuthProfile{}, OAuthState{}, ErrInvalidLogin
	}
	now := s.now()
	var binding OAuthState
	if durable, ok := s.store.(OAuthStateBindingStore); ok {
		var err error
		binding, ok, err = durable.ConsumeOAuthStateBinding(hashToken(stateToken), now)
		if err != nil {
			return OAuthProfile{}, OAuthState{}, err
		}
		if !ok {
			return OAuthProfile{}, OAuthState{}, ErrExpiredLogin
		}
	} else {
		s.mu.Lock()
		entry, found := s.states[stateToken]
		if found {
			delete(s.states, stateToken)
		}
		s.cleanupLocked(now)
		s.mu.Unlock()
		if !found || !now.Before(entry.expiresAt) {
			return OAuthProfile{}, OAuthState{}, ErrExpiredLogin
		}
		if s.store != nil {
			consumed, err := s.store.ConsumeOAuthState(hashToken(stateToken), now)
			if err != nil {
				return OAuthProfile{}, OAuthState{}, err
			}
			if !consumed {
				return OAuthProfile{}, OAuthState{}, ErrExpiredLogin
			}
		}
		binding = OAuthState{Provider: entry.provider, UserID: entry.userID}
	}
	profile, err := s.exchangeOAuth(request.Context(), binding.Provider, code)
	if err != nil {
		return OAuthProfile{}, OAuthState{}, err
	}
	return profile, binding, nil
}

func (s *LoginService) ResolveOAuth(ctx context.Context, profile OAuthProfile) (string, error) {
	if s.credentials == nil {
		return stableUserID(profile.Provider, profile.Subject), nil
	}
	if userID, err := s.credentials.FindOAuthUser(ctx, profile.Provider, profile.Subject); err == nil {
		return userID, nil
	} else if !errors.Is(err, ErrIdentityNotFound) {
		return "", err
	}
	emailHash := EmailHash(profile.Email)
	if emailHash == EmailHash("") {
		emailHash = EmailHash(profile.Provider + "\x00" + profile.Subject)
	}
	return s.credentials.CreateOAuthUser(ctx, profile, emailHash)
}

func (s *LoginService) LinkOAuth(ctx context.Context, userID string, profile OAuthProfile) error {
	if s.credentials == nil || !profile.EmailVerified || strings.TrimSpace(profile.Email) == "" {
		return ErrInvalidLogin
	}
	return s.credentials.LinkOAuthIdentity(ctx, userID, profile, EmailHash(profile.Email))
}

func (s *LoginService) ListOAuthIdentities(ctx context.Context, userID string) ([]LinkedIdentity, error) {
	if s.credentials == nil {
		return []LinkedIdentity{}, nil
	}
	return s.credentials.ListOAuthIdentities(ctx, userID)
}

func (s *LoginService) UnlinkOAuth(ctx context.Context, userID, provider string) error {
	if s.credentials == nil {
		return ErrLoginNotConfigured
	}
	return s.credentials.UnlinkOAuthIdentity(ctx, userID, provider)
}

func (s *LoginService) oauthProvider(provider string) (OAuthProviderConfig, bool) {
	if config, ok := s.config.OAuthProviders[provider]; ok {
		return config, true
	}
	switch provider {
	case ProviderGoogle:
		return OAuthProviderConfig{ClientID: s.config.GoogleClientID, ClientSecret: s.config.GoogleClientSecret, RedirectURL: s.config.GoogleRedirectURL, TokenURL: s.config.GoogleTokenURL, UserInfoURL: s.config.GoogleUserInfoURL}, true
	case ProviderApple:
		return OAuthProviderConfig{ClientID: s.config.AppleClientID, ClientSecret: s.config.AppleClientSecret, RedirectURL: s.config.AppleRedirectURL, AuthURL: s.config.AppleAuthURL, TokenURL: s.config.AppleTokenURL, JWKSURL: s.config.AppleJWKSURL}, true
	case ProviderGitHub:
		return OAuthProviderConfig{ClientID: s.config.GitHubClientID, ClientSecret: s.config.GitHubClientSecret, RedirectURL: s.config.GitHubRedirectURL, AuthURL: s.config.GitHubAuthURL, TokenURL: s.config.GitHubTokenURL, UserInfoURL: s.config.GitHubUserInfoURL, EmailURL: s.config.GitHubEmailURL}, true
	default:
		return OAuthProviderConfig{}, false
	}
}

func (s *LoginService) exchangeOAuth(ctx context.Context, provider, code string) (OAuthProfile, error) {
	config, ok := s.oauthProvider(provider)
	if !ok {
		return OAuthProfile{}, ErrInvalidLogin
	}
	clientSecret, err := s.oauthClientSecret(provider, config)
	if err != nil {
		return OAuthProfile{}, err
	}
	tokenURL := config.TokenURL
	if tokenURL == "" {
		switch provider {
		case ProviderGoogle:
			tokenURL = "https://oauth2.googleapis.com/token"
		case ProviderGitHub:
			tokenURL = "https://github.com/login/oauth/access_token"
		case ProviderApple:
			tokenURL = "https://appleid.apple.com/auth/token"
		}
	}
	form := url.Values{"code": {code}, "client_id": {config.ClientID}, "client_secret": {clientSecret}, "redirect_uri": {config.RedirectURL}, "grant_type": {"authorization_code"}}
	tokenRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return OAuthProfile{}, err
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if provider == ProviderGitHub {
		tokenRequest.Header.Set("Accept", "application/json")
	}
	tokenResponse, err := s.client.Do(tokenRequest)
	if err != nil {
		return OAuthProfile{}, err
	}
	defer tokenResponse.Body.Close()
	if tokenResponse.StatusCode < 200 || tokenResponse.StatusCode >= 300 {
		return OAuthProfile{}, ErrInvalidLogin
	}
	var token struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(tokenResponse.Body).Decode(&token); err != nil {
		return OAuthProfile{}, ErrInvalidLogin
	}
	if provider == ProviderApple {
		return s.appleProfile(ctx, token.IDToken, config)
	}
	if token.AccessToken == "" {
		return OAuthProfile{}, ErrInvalidLogin
	}
	return s.userInfoProfile(ctx, provider, token.AccessToken, config)
}

func (s *LoginService) userInfoProfile(ctx context.Context, provider, accessToken string, config OAuthProviderConfig) (OAuthProfile, error) {
	userInfoURL := config.UserInfoURL
	if userInfoURL == "" {
		if provider == ProviderGoogle {
			userInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
		} else {
			userInfoURL = "https://api.github.com/user"
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return OAuthProfile{}, err
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return OAuthProfile{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return OAuthProfile{}, ErrInvalidLogin
	}
	if provider == ProviderGitHub {
		var profile struct {
			ID    json.Number `json:"id"`
			Email string      `json:"email"`
		}
		if err := json.NewDecoder(response.Body).Decode(&profile); err != nil || profile.ID.String() == "" {
			return OAuthProfile{}, ErrInvalidLogin
		}
		email, verified := profile.Email, false
		emailURL := config.EmailURL
		if emailURL == "" && userInfoURL == "https://api.github.com/user" {
			emailURL = "https://api.github.com/user/emails"
		}
		if emailURL != "" {
			email, verified = s.githubEmail(ctx, accessToken, emailURL, email)
		}
		return OAuthProfile{Provider: provider, Subject: profile.ID.String(), Email: email, EmailVerified: verified}, nil
	}
	var profile struct {
		Subject  string `json:"sub"`
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := json.NewDecoder(response.Body).Decode(&profile); err != nil || profile.Subject == "" {
		return OAuthProfile{}, ErrInvalidLogin
	}
	if profile.Email != "" && !profile.Verified {
		return OAuthProfile{}, ErrInvalidLogin
	}
	return OAuthProfile{Provider: provider, Subject: profile.Subject, Email: profile.Email, EmailVerified: profile.Verified}, nil
}

func (s *LoginService) githubEmail(ctx context.Context, accessToken, emailURL, fallback string) (string, bool) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, emailURL, nil)
	if err != nil {
		return fallback, false
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/vnd.github+json")
	response, err := s.client.Do(request)
	if err != nil {
		return fallback, false
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fallback, false
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(response.Body).Decode(&emails); err != nil {
		return fallback, false
	}
	for _, item := range emails {
		if item.Verified && item.Primary {
			return item.Email, true
		}
	}
	for _, item := range emails {
		if item.Verified {
			return item.Email, true
		}
	}
	return fallback, false
}

func (s *LoginService) oauthClientSecret(provider string, config OAuthProviderConfig) (string, error) {
	if provider != ProviderApple || strings.TrimSpace(config.ClientSecret) != "" {
		return config.ClientSecret, nil
	}
	if s.config.AppleTeamID == "" || s.config.AppleKeyID == "" || s.config.ApplePrivateKey == "" {
		return "", ErrLoginNotConfigured
	}
	block, _ := pem.Decode([]byte(strings.ReplaceAll(s.config.ApplePrivateKey, `\n`, "\n")))
	if block == nil {
		return "", ErrLoginNotConfigured
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if parsed, parseErr := x509.ParseECPrivateKey(block.Bytes); parseErr == nil {
			key = parsed
		} else {
			return "", ErrLoginNotConfigured
		}
	}
	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve != elliptic.P256() {
		return "", ErrLoginNotConfigured
	}
	encode := func(value any) string {
		payload, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(payload)
	}
	header := encode(map[string]string{"alg": "ES256", "kid": s.config.AppleKeyID, "typ": "JWT"})
	now := s.now().Unix()
	payload := encode(map[string]any{"iss": s.config.AppleTeamID, "iat": now, "exp": now + 300, "aud": "https://appleid.apple.com", "sub": config.ClientID})
	message := header + "." + payload
	digest := sha256.Sum256([]byte(message))
	r, ss, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		return "", err
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	ss.FillBytes(signature[32:])
	return message + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (s *LoginService) appleProfile(ctx context.Context, token string, config OAuthProviderConfig) (OAuthProfile, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return OAuthProfile{}, ErrInvalidLogin
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	if err := decodeJWTPart(parts[0], &header); err != nil || header.Algorithm != "RS256" || header.KeyID == "" {
		return OAuthProfile{}, ErrInvalidLogin
	}
	key, err := s.appleSigningKey(ctx, config, header.KeyID)
	if err != nil {
		return OAuthProfile{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err != nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return OAuthProfile{}, ErrInvalidLogin
	}
	var claims struct {
		Issuer         string          `json:"iss"`
		Audience       json.RawMessage `json:"aud"`
		Subject        string          `json:"sub"`
		Email          string          `json:"email"`
		EmailVerified  json.RawMessage `json:"email_verified"`
		ExpirationTime int64           `json:"exp"`
	}
	if err := decodeJWTPart(parts[1], &claims); err != nil || claims.Issuer != "https://appleid.apple.com" || claims.Subject == "" || claims.ExpirationTime <= s.now().Unix() || !audienceContains(claims.Audience, config.ClientID) {
		return OAuthProfile{}, ErrInvalidLogin
	}
	verified := string(claims.EmailVerified) == "true" || strings.Trim(string(claims.EmailVerified), `"`) == "true"
	return OAuthProfile{Provider: ProviderApple, Subject: claims.Subject, Email: claims.Email, EmailVerified: verified || claims.Email == ""}, nil
}

func (s *LoginService) appleSigningKey(ctx context.Context, config OAuthProviderConfig, keyID string) (*rsa.PublicKey, error) {
	jwksURL := config.JWKSURL
	if jwksURL == "" {
		jwksURL = "https://appleid.apple.com/auth/keys"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, ErrInvalidLogin
	}
	var keys struct {
		Keys []struct {
			KeyType string `json:"kty"`
			KeyID   string `json:"kid"`
			N       string `json:"n"`
			E       string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&keys); err != nil {
		return nil, ErrInvalidLogin
	}
	for _, candidate := range keys.Keys {
		if candidate.KeyType != "RSA" || candidate.KeyID != keyID {
			continue
		}
		modulus, err := base64.RawURLEncoding.DecodeString(candidate.N)
		if err != nil {
			return nil, ErrInvalidLogin
		}
		exponentBytes, err := base64.RawURLEncoding.DecodeString(candidate.E)
		if err != nil || len(exponentBytes) > 8 {
			return nil, ErrInvalidLogin
		}
		var exponent uint64
		for _, value := range exponentBytes {
			exponent = exponent<<8 | uint64(value)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(exponent)}, nil
	}
	return nil, ErrInvalidLogin
}

func decodeJWTPart(value string, destination any) error {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(decoded, destination)
}

func audienceContains(raw json.RawMessage, expected string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == expected
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil {
		return false
	}
	for _, item := range many {
		if item == expected {
			return true
		}
	}
	return false
}
