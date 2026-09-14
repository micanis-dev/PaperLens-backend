package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config contains runtime configuration. Secrets are deliberately read only
// from the environment and are never included in logs or API responses.
type Config struct {
	AppEnv                string
	BaseURL               string
	HTTPAddr              string
	DatabaseURL           string
	FrontendOrigins       []string
	AdminUserIDs          []string
	ManagedLLMBaseURL     string
	ManagedLLMAPIKey      string
	ManagedLLMModel       string
	SessionCookieName     string
	SessionSecret         string
	GoogleClientID        string
	GoogleClientSecret    string
	GoogleRedirectURL     string
	FrontendBaseURL       string
	MagicLinkBaseURL      string
	SMTPHost              string
	SMTPPort              string
	SMTPUsername          string
	SMTPPassword          string
	SMTPFrom              string
	StripeSecretKey       string
	StripeWebhookSecret   string
	StripePricePlus       string
	StripePricePro        string
	StripePriceUltra      string
	StripeAPIBaseURL      string
	StripeSuccessURL      string
	StripeCancelURL       string
	StripePortalReturnURL string
	ShutdownTimeout       time.Duration
}

func Load() (Config, error) {
	timeout, err := durationEnv("SHUTDOWN_TIMEOUT", 10*time.Second)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		AppEnv:                envOr("APP_ENV", "development"),
		BaseURL:               envOr("APP_BASE_URL", "http://127.0.0.1:8080"),
		HTTPAddr:              envOr("HTTP_ADDR", "127.0.0.1:8080"),
		DatabaseURL:           os.Getenv("DATABASE_URL"),
		FrontendOrigins:       csvEnv("FRONTEND_ORIGINS", []string{"http://127.0.0.1:5173"}),
		AdminUserIDs:          csvEnv("ADMIN_USER_IDS", nil),
		ManagedLLMBaseURL:     os.Getenv("PAPERLENS_LLM_BASE_URL"),
		ManagedLLMAPIKey:      os.Getenv("PAPERLENS_LLM_API_KEY"),
		ManagedLLMModel:       os.Getenv("PAPERLENS_LLM_MODEL"),
		SessionCookieName:     envOr("SESSION_COOKIE_NAME", "paperlens_session"),
		SessionSecret:         os.Getenv("SESSION_SECRET"),
		GoogleClientID:        os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret:    os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL:     os.Getenv("GOOGLE_REDIRECT_URL"),
		FrontendBaseURL:       envOr("FRONTEND_BASE_URL", "http://127.0.0.1:5173"),
		MagicLinkBaseURL:      envOr("MAGIC_LINK_BASE_URL", "http://127.0.0.1:8080/v1/auth/magic-link/verify"),
		SMTPHost:              os.Getenv("SMTP_HOST"),
		SMTPPort:              envOr("SMTP_PORT", "587"),
		SMTPUsername:          os.Getenv("SMTP_USERNAME"),
		SMTPPassword:          os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:              os.Getenv("SMTP_FROM"),
		StripeSecretKey:       os.Getenv("STRIPE_SECRET_KEY"),
		StripeWebhookSecret:   os.Getenv("STRIPE_WEBHOOK_SECRET"),
		StripePricePlus:       os.Getenv("STRIPE_PRICE_PLUS"),
		StripePricePro:        os.Getenv("STRIPE_PRICE_PRO"),
		StripePriceUltra:      os.Getenv("STRIPE_PRICE_ULTRA"),
		StripeAPIBaseURL:      envOr("STRIPE_API_BASE_URL", "https://api.stripe.com"),
		StripeSuccessURL:      envOr("STRIPE_SUCCESS_URL", "http://127.0.0.1:5173/settings/?billing=success"),
		StripeCancelURL:       envOr("STRIPE_CANCEL_URL", "http://127.0.0.1:5173/settings/?billing=cancel"),
		StripePortalReturnURL: envOr("STRIPE_PORTAL_RETURN_URL", "http://127.0.0.1:5173/settings/"),
		ShutdownTimeout:       timeout,
	}

	if cfg.AppEnv == "production" && cfg.ManagedLLMAPIKey == "" {
		return Config{}, fmt.Errorf("PAPERLENS_LLM_API_KEY is required in production")
	}
	if cfg.AppEnv == "production" && cfg.ManagedLLMBaseURL == "" {
		return Config{}, fmt.Errorf("PAPERLENS_LLM_BASE_URL is required in production")
	}
	if cfg.AppEnv == "production" && cfg.ManagedLLMModel == "" {
		return Config{}, fmt.Errorf("PAPERLENS_LLM_MODEL is required in production")
	}
	if cfg.AppEnv == "production" && strings.TrimSpace(cfg.DatabaseURL) == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required in production")
	}
	if cfg.AppEnv == "production" && len(strings.TrimSpace(cfg.SessionSecret)) < 32 {
		return Config{}, fmt.Errorf("SESSION_SECRET must be at least 32 characters in production")
	}
	if cfg.AppEnv == "production" && len(cfg.AdminUserIDs) == 0 {
		return Config{}, fmt.Errorf("ADMIN_USER_IDS is required in production")
	}
	if cfg.AppEnv == "production" {
		for name, value := range map[string]string{
			"APP_BASE_URL": cfg.BaseURL, "FRONTEND_BASE_URL": cfg.FrontendBaseURL,
			"MAGIC_LINK_BASE_URL": cfg.MagicLinkBaseURL, "STRIPE_SUCCESS_URL": cfg.StripeSuccessURL,
			"STRIPE_CANCEL_URL": cfg.StripeCancelURL, "STRIPE_PORTAL_RETURN_URL": cfg.StripePortalReturnURL,
		} {
			if err := requireHTTPSURL(name, value); err != nil {
				return Config{}, err
			}
		}
		for _, origin := range cfg.FrontendOrigins {
			if err := requireHTTPSURL("FRONTEND_ORIGINS", origin); err != nil {
				return Config{}, err
			}
		}
	}
	stripeValues := []string{cfg.StripeSecretKey, cfg.StripeWebhookSecret, cfg.StripePricePlus, cfg.StripePricePro, cfg.StripePriceUltra}
	stripeConfigured := false
	for _, value := range stripeValues {
		if strings.TrimSpace(value) != "" {
			stripeConfigured = true
			break
		}
	}
	if stripeConfigured {
		for name, value := range map[string]string{"STRIPE_SECRET_KEY": cfg.StripeSecretKey, "STRIPE_WEBHOOK_SECRET": cfg.StripeWebhookSecret, "STRIPE_PRICE_PLUS": cfg.StripePricePlus, "STRIPE_PRICE_PRO": cfg.StripePricePro, "STRIPE_PRICE_ULTRA": cfg.StripePriceUltra} {
			if strings.TrimSpace(value) == "" {
				return Config{}, fmt.Errorf("%s must be configured with the other Stripe settings", name)
			}
		}
	}
	return cfg, nil
}

func requireHTTPSURL(name, value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("%s must be an absolute HTTPS URL in production", name)
	}
	return nil
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func csvEnv(key string, fallback []string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return fallback
	}
	return result
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return duration, nil
}
