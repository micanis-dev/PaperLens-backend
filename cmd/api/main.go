package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/micanis/paperlens/backend/internal/account"
	"github.com/micanis/paperlens/backend/internal/api"
	"github.com/micanis/paperlens/backend/internal/auth"
	"github.com/micanis/paperlens/backend/internal/billing"
	"github.com/micanis/paperlens/backend/internal/config"
	"github.com/micanis/paperlens/backend/internal/credits"
	"github.com/micanis/paperlens/backend/internal/observability"
	"github.com/micanis/paperlens/backend/internal/persistence"
	"github.com/micanis/paperlens/backend/internal/provider"
	"github.com/micanis/paperlens/backend/internal/translation"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	var ledger credits.Store = credits.NewLedger(time.Now)
	var repository translation.Repository = translation.NewMemoryRepository()
	var revoked auth.SessionRevocationStore = auth.NewRevokedSessions()
	var billingStore billing.Store = billing.NewMemoryStore()
	var accountStore account.Store = account.NewMemoryStore()
	var database *sql.DB
	if cfg.DatabaseURL != "" {
		database, err = persistence.Open(context.Background(), cfg.DatabaseURL)
		if err != nil {
			logger.Error("database connection failed", "error", err)
			os.Exit(1)
		}
		defer database.Close()
		if err := persistence.Migrate(context.Background(), database); err != nil {
			logger.Error("database migration failed", "error", err)
			os.Exit(1)
		}
		ledger = persistence.NewPostgresLedger(database, time.Now)
		repository = persistence.NewTranslationRepository(database)
		revoked = persistence.NewPostgresRevocations(database)
		billingStore = persistence.NewPostgresBillingStore(database)
		accountStore = persistence.NewPostgresAccountStore(database)
	}
	translationProvider := selectProvider(cfg)
	metrics := observability.NewMetrics()
	service := translation.NewService(repository, ledger, translationProvider, time.Now).WithObserver(metrics)
	var ratePolicyStore *persistence.PostgresRatePolicyStore
	if database != nil {
		ratePolicyStore = persistence.NewPostgresRatePolicyStore(database)
		if policy, loadErr := ratePolicyStore.Get(context.Background()); loadErr == nil {
			if setErr := service.SetRatePolicy(policy); setErr != nil {
				logger.Error("stored rate policy is invalid", "error", setErr)
				os.Exit(1)
			}
		} else if !errors.Is(loadErr, sql.ErrNoRows) {
			logger.Error("rate policy could not be loaded", "error", loadErr)
			os.Exit(1)
		}
	}
	billingConfig := billing.Config{SecretKey: cfg.StripeSecretKey, WebhookSecret: cfg.StripeWebhookSecret, APIBaseURL: cfg.StripeAPIBaseURL, SuccessURL: cfg.StripeSuccessURL, CancelURL: cfg.StripeCancelURL, PortalReturnURL: cfg.StripePortalReturnURL, PriceIDs: map[string]string{"plus": cfg.StripePricePlus, "pro": cfg.StripePricePro, "ultra": cfg.StripePriceUltra}}
	billingService := billing.NewService(billingStore, billing.HTTPProvider{SecretKey: cfg.StripeSecretKey, BaseURL: cfg.StripeAPIBaseURL, Client: &http.Client{Timeout: 15 * time.Second}}, billingConfig, time.Now)
	if database == nil {
		// The memory billing store and memory credit ledger have separate state,
		// so local development needs an explicit synchronization callback.
		billingService.WithPlanSink(ledger.SetPlan)
	}
	if database == nil {
		billingService.WithSubscriptionSink(func(userID string, subscription billing.Subscription) error {
			if periodStore, ok := ledger.(credits.BillingPeriodStore); ok && !subscription.CurrentPeriodStart.IsZero() && !subscription.CurrentPeriodEnd.IsZero() {
				return periodStore.SetBillingPeriod(userID, subscription.PlanID, subscription.CurrentPeriodStart, subscription.CurrentPeriodEnd)
			}
			return ledger.SetPlan(userID, subscription.PlanID)
		})
	}
	sessionSecret := cfg.SessionSecret
	if sessionSecret == "" && cfg.AppEnv != "production" {
		// This fallback is deliberately development-only. Production refuses an
		// unset secret during config validation.
		sessionSecret = "paperlens-development-session-secret-change-me"
	}
	authenticator := auth.SessionAuthenticator{
		CookieName: cfg.SessionCookieName,
		DevUserID:  "local-development-user",
		Production: cfg.AppEnv == "production",
		Secret:     []byte(sessionSecret),
		Revoked:    revoked,
	}
	loginConfig := auth.LoginConfig{
		AppEnv: cfg.AppEnv, GoogleClientID: cfg.GoogleClientID, GoogleClientSecret: cfg.GoogleClientSecret,
		GoogleRedirectURL: cfg.GoogleRedirectURL, AppleClientID: cfg.AppleClientID, AppleClientSecret: cfg.AppleClientSecret,
		AppleRedirectURL: cfg.AppleRedirectURL, AppleTeamID: cfg.AppleTeamID, AppleKeyID: cfg.AppleKeyID, ApplePrivateKey: cfg.ApplePrivateKey,
		AppleAuthURL: cfg.AppleAuthURL, AppleTokenURL: cfg.AppleTokenURL, AppleJWKSURL: cfg.AppleJWKSURL,
		GitHubClientID: cfg.GitHubClientID, GitHubClientSecret: cfg.GitHubClientSecret, GitHubRedirectURL: cfg.GitHubRedirectURL,
		GitHubAuthURL: cfg.GitHubAuthURL, GitHubTokenURL: cfg.GitHubTokenURL, GitHubUserInfoURL: cfg.GitHubUserInfoURL, GitHubEmailURL: cfg.GitHubEmailURL,
		FrontendBaseURL: cfg.FrontendBaseURL, MagicLinkBaseURL: cfg.MagicLinkBaseURL,
		SMTPHost: cfg.SMTPHost, SMTPPort: cfg.SMTPPort, SMTPUsername: cfg.SMTPUsername, SMTPPassword: cfg.SMTPPassword, SMTPFrom: cfg.SMTPFrom,
	}
	var emailSender auth.EmailSender
	if loginConfig.SMTPHost != "" && loginConfig.SMTPFrom != "" {
		emailSender = auth.SMTPEmailSender(loginConfig)
	}
	loginService := auth.NewLoginService(loginConfig, nil, emailSender, time.Now)
	var credentialStore auth.CredentialStore = auth.NewMemoryCredentialStore()
	if database != nil {
		loginService.WithStore(persistence.NewPostgresLoginStore(database))
		credentialStore = persistence.NewPostgresCredentialStore(database)
	}
	loginService.WithCredentialStore(credentialStore)
	accountService := account.NewService(accountStore, time.Now)
	if cfg.AppEnv != "production" {
		for _, testUser := range cfg.DevTestUsers {
			if err := accountService.Ensure(context.Background(), testUser.ID); err != nil {
				logger.Warn("development test user could not be provisioned", "user_id", testUser.ID, "error", err)
			}
		}
	}
	handler := api.NewHandler(cfg, authenticator, ledger, service).WithMetrics(metrics).WithLoginService(loginService).WithBillingService(billingService).WithAccountService(accountService)
	if ratePolicyStore != nil {
		handler.WithRatePolicyPersistence(ratePolicyStore.Save)
	}
	if database != nil {
		handler.WithHealthCheck(database.PingContext)
	}
	server := &http.Server{Addr: cfg.HTTPAddr, Handler: handler.Routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 120 * time.Second}
	deletionCtx, stopDeletionWorker := context.WithCancel(context.Background())
	defer stopDeletionWorker()
	if err := service.ReconcileStale(context.Background(), time.Now().Add(-translation.StaleTranslationAge)); err != nil {
		logger.Error("stale translation reconciliation failed", "error", err)
	}
	go func() {
		// Deletion is also checked on authenticated requests, but this worker
		// ensures the 24-hour grace period is enforced even when a user is idle.
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if count, err := accountService.ProcessDueAccounts(deletionCtx); err != nil {
					logger.Error("account deletion sweep failed", "error", err)
				} else if count > 0 {
					logger.Info("account deletion sweep completed", "deleted", count)
				}
			case <-deletionCtx.Done():
				return
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				if err := service.ReconcileStale(deletionCtx, now.Add(-translation.StaleTranslationAge)); err != nil {
					logger.Error("stale translation reconciliation failed", "error", err)
				}
			case <-deletionCtx.Done():
				return
			}
		}
	}()

	go func() {
		logger.Info("paperlens api listening", "addr", cfg.HTTPAddr, "env", cfg.AppEnv, "provider", translationProvider.Name())
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server stopped", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
}

func selectProvider(cfg config.Config) provider.Provider {
	if cfg.AppEnv != "production" && cfg.ManagedLLMAPIKey == "" {
		return provider.EchoProvider{}
	}
	if cfg.ManagedLLMAPIKey != "" && cfg.ManagedLLMBaseURL != "" && cfg.ManagedLLMModel != "" {
		return provider.OpenAICompatibleProvider{BaseURL: cfg.ManagedLLMBaseURL, APIKey: cfg.ManagedLLMAPIKey, ModelName: cfg.ManagedLLMModel, Client: &http.Client{Timeout: 90 * time.Second}}
	}
	return provider.UnconfiguredProvider{}
}
