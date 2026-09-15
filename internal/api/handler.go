package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/micanis/paperlens/backend/internal/account"
	"github.com/micanis/paperlens/backend/internal/auth"
	"github.com/micanis/paperlens/backend/internal/billing"
	"github.com/micanis/paperlens/backend/internal/config"
	"github.com/micanis/paperlens/backend/internal/contract"
	"github.com/micanis/paperlens/backend/internal/credits"
	"github.com/micanis/paperlens/backend/internal/httpx"
	"github.com/micanis/paperlens/backend/internal/observability"
	"github.com/micanis/paperlens/backend/internal/translation"
)

type Handler struct {
	config         config.Config
	auth           auth.Authenticator
	login          *auth.LoginService
	billing        *billing.Service
	accountService *account.Service
	ledger         credits.Store
	service        *translation.Service
	saveRatePolicy func(context.Context, credits.RatePolicy) error
	started        time.Time
	healthCheck    func(context.Context) error
	metrics        *observability.Metrics
}

func (h *Handler) WithHealthCheck(check func(context.Context) error) *Handler {
	h.healthCheck = check
	return h
}

func (h *Handler) WithMetrics(metrics *observability.Metrics) *Handler {
	h.metrics = metrics
	return h
}

func (h *Handler) WithLoginService(login *auth.LoginService) *Handler {
	h.login = login
	return h
}

func (h *Handler) WithBillingService(service *billing.Service) *Handler {
	h.billing = service
	return h
}

func (h *Handler) WithAccountService(service *account.Service) *Handler {
	h.accountService = service
	return h
}

func (h *Handler) WithRatePolicyPersistence(save func(context.Context, credits.RatePolicy) error) *Handler {
	h.saveRatePolicy = save
	return h
}

func NewHandler(cfg config.Config, authenticator auth.Authenticator, ledger credits.Store, service *translation.Service) *Handler {
	return &Handler{config: cfg, auth: authenticator, ledger: ledger, service: service, started: time.Now().UTC(), metrics: observability.NewMetrics()}
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/healthz", h.health)
	mux.HandleFunc("GET /v1/internal/metrics", h.metricsEndpoint)
	mux.HandleFunc("POST /v1/auth/logout", h.logout)
	mux.HandleFunc("POST /v1/auth/register", h.registerPassword)
	mux.HandleFunc("POST /v1/auth/login", h.loginPassword)
	mux.HandleFunc("GET /v1/auth/google", h.googleLogin)
	mux.HandleFunc("GET /v1/auth/google/signup", h.googleSignup)
	mux.HandleFunc("GET /v1/auth/google/callback", h.googleCallback)
	mux.HandleFunc("GET /v1/auth/apple", h.oauthLogin)
	mux.HandleFunc("GET /v1/auth/apple/signup", h.oauthLogin)
	mux.HandleFunc("GET /v1/auth/apple/callback", h.oauthCallback)
	mux.HandleFunc("GET /v1/auth/github", h.oauthLogin)
	mux.HandleFunc("GET /v1/auth/github/signup", h.oauthLogin)
	mux.HandleFunc("GET /v1/auth/github/callback", h.oauthCallback)
	mux.HandleFunc("GET /v1/auth/link/{provider}", h.linkOAuth)
	mux.HandleFunc("GET /v1/auth/identities", h.identities)
	mux.HandleFunc("DELETE /v1/auth/identities/{provider}", h.unlinkOAuth)
	mux.HandleFunc("GET /v1/auth/test-users", h.listDevTestUsers)
	mux.HandleFunc("POST /v1/auth/test-users/{id}", h.loginDevTestUser)
	mux.HandleFunc("POST /v1/auth/magic-link", h.requestMagicLink)
	mux.HandleFunc("GET /v1/auth/magic-link/verify", h.verifyMagicLink)
	mux.HandleFunc("GET /v1/plans", h.plans)
	mux.HandleFunc("GET /v1/billing", h.billingInfo)
	mux.HandleFunc("POST /v1/checkout", h.checkout)
	mux.HandleFunc("POST /v1/billing/change-plan", h.changePlan)
	mux.HandleFunc("POST /v1/portal", h.portal)
	mux.HandleFunc("POST /v1/stripe/webhook", h.stripeWebhook)
	mux.HandleFunc("GET /v1/account", h.account)
	mux.HandleFunc("POST /v1/account/deletion", h.requestAccountDeletion)
	mux.HandleFunc("POST /v1/account/deletion/cancel", h.cancelAccountDeletion)
	mux.HandleFunc("GET /v1/credits", h.credits)
	mux.HandleFunc("GET /v1/usage", h.usage)
	mux.HandleFunc("GET /v1/admin/rates", h.adminRates)
	mux.HandleFunc("PUT /v1/admin/rates", h.updateAdminRates)
	mux.HandleFunc("POST /v1/translations/estimate", h.estimate)
	mux.HandleFunc("POST /v1/translations", h.startTranslation)
	mux.HandleFunc("GET /v1/translations/{id}", h.getTranslation)
	mux.HandleFunc("POST /v1/translations/{id}/cancel", h.cancelTranslation)
	return h.withMetrics(h.withRequestContext(h.withCORS(h.withRateLimits(mux))))
}

type sessionRevoker interface {
	Revoke(*http.Request)
}

func (h *Handler) logout(w http.ResponseWriter, request *http.Request) {
	if revoker, ok := h.auth.(sessionRevoker); ok {
		revoker.Revoke(request)
	}
	http.SetCookie(w, &http.Cookie{Name: h.config.SessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: h.config.AppEnv == "production", SameSite: http.SameSiteLaxMode})
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "loggedOut": true})
}

type sessionIssuer interface {
	SetSessionCookie(http.ResponseWriter, string) error
}

type sessionRefresher interface {
	RefreshSessionCookie(http.ResponseWriter, *http.Request)
}

func (h *Handler) googleLogin(w http.ResponseWriter, request *http.Request) {
	h.oauthLogin(w, request)
}

func (h *Handler) oauthLogin(w http.ResponseWriter, request *http.Request) {
	if h.login == nil {
		h.loginError(w, request, auth.ErrLoginNotConfigured)
		return
	}
	location, err := h.login.OAuthURL(oauthProviderFromPath(request), "")
	if err != nil {
		h.loginError(w, request, err)
		return
	}
	http.Redirect(w, request, location, http.StatusFound)
}

// googleSignup intentionally uses the same OAuth flow as login. Google is
// the identity provider; whether the stable identity is new or existing is
// resolved by the account provisioning step after the callback.
func (h *Handler) googleSignup(w http.ResponseWriter, request *http.Request) {
	h.googleLogin(w, request)
}

func (h *Handler) googleCallback(w http.ResponseWriter, request *http.Request) {
	h.oauthCallback(w, request)
}

func (h *Handler) oauthCallback(w http.ResponseWriter, request *http.Request) {
	if h.login == nil {
		h.loginError(w, request, auth.ErrLoginNotConfigured)
		return
	}
	profile, state, err := h.login.CompleteOAuth(request)
	if err != nil {
		h.loginError(w, request, err)
		return
	}
	if profile.Provider != oauthProviderFromPath(request) {
		h.loginError(w, request, auth.ErrInvalidLogin)
		return
	}
	if state.UserID != "" {
		identity, authenticated := h.auth.Authenticate(request)
		if !authenticated || identity.UserID != state.UserID {
			h.loginError(w, request, auth.ErrInvalidCredentials)
			return
		}
		if err := h.login.LinkOAuth(request.Context(), state.UserID, profile); err != nil {
			h.loginError(w, request, err)
			return
		}
		http.Redirect(w, request, h.login.FrontendBaseURL()+"/settings/?sso=linked&provider="+url.QueryEscape(profile.Provider), http.StatusFound)
		return
	}
	userID, err := h.login.ResolveOAuth(request.Context(), profile)
	if err != nil {
		h.loginError(w, request, err)
		return
	}
	if h.accountService != nil {
		if err := h.accountService.Ensure(request.Context(), userID); err != nil {
			h.loginError(w, request, err)
			return
		}
	}
	if !h.issueSession(w, userID, request) {
		return
	}
	http.Redirect(w, request, h.login.FrontendBaseURL(), http.StatusFound)
}

func (h *Handler) registerPassword(w http.ResponseWriter, request *http.Request) {
	if h.login == nil {
		h.loginError(w, request, auth.ErrLoginNotConfigured)
		return
	}
	var payload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !h.decodeJSON(w, request, &payload) {
		return
	}
	userID, err := h.login.RegisterPassword(payload.Email, payload.Password)
	if err != nil {
		h.loginError(w, request, err)
		return
	}
	if h.accountService != nil {
		if err := h.accountService.Ensure(request.Context(), userID); err != nil {
			h.loginError(w, request, err)
			return
		}
	}
	if !h.issueSession(w, userID, request) {
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]any{"requestId": httpx.RequestID(request), "registered": true})
}

func (h *Handler) loginPassword(w http.ResponseWriter, request *http.Request) {
	if h.login == nil {
		h.loginError(w, request, auth.ErrLoginNotConfigured)
		return
	}
	var payload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !h.decodeJSON(w, request, &payload) {
		return
	}
	userID, err := h.login.LoginPassword(payload.Email, payload.Password)
	if err != nil {
		h.loginError(w, request, err)
		return
	}
	if h.accountService != nil {
		if err := h.accountService.Ensure(request.Context(), userID); err != nil {
			h.loginError(w, request, err)
			return
		}
	}
	if !h.issueSession(w, userID, request) {
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "loggedIn": true})
}

func (h *Handler) linkOAuth(w http.ResponseWriter, request *http.Request) {
	identity, ok := h.identity(w, request)
	if !ok || h.login == nil {
		return
	}
	location, err := h.login.OAuthURL(request.PathValue("provider"), identity.UserID)
	if err != nil {
		h.loginError(w, request, err)
		return
	}
	http.Redirect(w, request, location, http.StatusFound)
}

func (h *Handler) identities(w http.ResponseWriter, request *http.Request) {
	identity, ok := h.identity(w, request)
	if !ok || h.login == nil {
		return
	}
	items, err := h.login.ListOAuthIdentities(request.Context(), identity.UserID)
	if err != nil {
		h.loginError(w, request, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "identities": items})
}

func (h *Handler) unlinkOAuth(w http.ResponseWriter, request *http.Request) {
	identity, ok := h.identity(w, request)
	if !ok || h.login == nil {
		return
	}
	if err := h.login.UnlinkOAuth(request.Context(), identity.UserID, request.PathValue("provider")); err != nil {
		h.loginError(w, request, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "unlinked": true})
}

func oauthProviderFromPath(request *http.Request) string {
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

func (h *Handler) requestMagicLink(w http.ResponseWriter, request *http.Request) {
	if h.login == nil {
		h.loginError(w, request, auth.ErrLoginNotConfigured)
		return
	}
	var payload struct {
		Email string `json:"email"`
	}
	if !h.decodeJSON(w, request, &payload) {
		return
	}
	token, err := h.login.RequestMagicLink(payload.Email)
	if err != nil {
		h.loginError(w, request, err)
		return
	}
	response := map[string]any{"requestId": httpx.RequestID(request), "sent": true}
	// This branch is intentionally development-only. It lets a local install
	// exercise the complete cookie flow without placing a token in production
	// responses or logs.
	if h.config.AppEnv != "production" {
		response["devToken"] = token
	}
	httpx.JSON(w, http.StatusOK, response)
}

func (h *Handler) verifyMagicLink(w http.ResponseWriter, request *http.Request) {
	if h.login == nil {
		h.loginError(w, request, auth.ErrLoginNotConfigured)
		return
	}
	userID, err := h.login.ConsumeMagicLink(request.URL.Query().Get("token"))
	if err != nil {
		h.loginError(w, request, err)
		return
	}
	if h.accountService != nil {
		if err := h.accountService.Ensure(request.Context(), userID); err != nil {
			h.loginError(w, request, err)
			return
		}
	}
	if !h.issueSession(w, userID, request) {
		return
	}
	http.Redirect(w, request, h.login.FrontendBaseURL(), http.StatusFound)
}

func (h *Handler) issueSession(w http.ResponseWriter, userID string, request *http.Request) bool {
	issuer, ok := h.auth.(sessionIssuer)
	if !ok {
		h.loginError(w, request, auth.ErrLoginNotConfigured)
		return false
	}
	if err := issuer.SetSessionCookie(w, userID); err != nil {
		h.loginError(w, request, err)
		return false
	}
	return true
}

func (h *Handler) loginError(w http.ResponseWriter, request *http.Request, err error) {
	code := contract.ErrProviderUnavailable
	status := http.StatusServiceUnavailable
	message := "login is temporarily unavailable"
	if errors.Is(err, auth.ErrInvalidLogin) || errors.Is(err, auth.ErrExpiredLogin) {
		code = contract.ErrInvalidRequest
		status = http.StatusBadRequest
		message = "the login link or authorization response is invalid"
	} else if errors.Is(err, account.ErrAlreadyDeleted) {
		code = contract.ErrForbidden
		status = http.StatusForbidden
		message = "this account is no longer available"
	} else if errors.Is(err, auth.ErrInvalidCredentials) {
		code = contract.ErrUnauthorized
		status = http.StatusUnauthorized
		message = "email or password is incorrect"
	} else if errors.Is(err, auth.ErrEmailAlreadyRegistered) {
		code = contract.ErrInvalidRequest
		status = http.StatusConflict
		message = "this email address is already registered"
	} else if errors.Is(err, auth.ErrPasswordTooShort) {
		code = contract.ErrInvalidRequest
		status = http.StatusBadRequest
		message = "password must be at least 12 characters"
	} else if errors.Is(err, auth.ErrIdentityAlreadyLinked) {
		code = contract.ErrInvalidRequest
		status = http.StatusConflict
		message = "this SSO account is already linked"
	} else if errors.Is(err, auth.ErrIdentityNotLinked) || errors.Is(err, auth.ErrLastAuthMethod) {
		code = contract.ErrInvalidRequest
		status = http.StatusBadRequest
		message = "the SSO account could not be unlinked"
	}
	httpx.Error(w, status, httpx.RequestID(request), code, message, status >= 500)
}

func (h *Handler) listDevTestUsers(w http.ResponseWriter, request *http.Request) {
	if h.config.AppEnv == "production" || len(h.config.DevTestUsers) == 0 {
		http.NotFound(w, request)
		return
	}
	users := make([]map[string]string, 0, len(h.config.DevTestUsers))
	for _, user := range h.config.DevTestUsers {
		users = append(users, map[string]string{"id": user.ID, "label": user.Label})
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "users": users})
}

func (h *Handler) loginDevTestUser(w http.ResponseWriter, request *http.Request) {
	if h.config.AppEnv == "production" {
		http.NotFound(w, request)
		return
	}
	id := request.PathValue("id")
	var selected *config.DevTestUser
	for index := range h.config.DevTestUsers {
		if h.config.DevTestUsers[index].ID == id {
			selected = &h.config.DevTestUsers[index]
			break
		}
	}
	if selected == nil {
		http.NotFound(w, request)
		return
	}
	if h.accountService != nil {
		if err := h.accountService.Ensure(request.Context(), selected.ID); err != nil {
			h.loginError(w, request, err)
			return
		}
	}
	if !h.issueSession(w, selected.ID, request) {
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"requestId": httpx.RequestID(request),
		"user":      map[string]string{"id": selected.ID, "label": selected.Label},
	})
}

func (h *Handler) health(w http.ResponseWriter, request *http.Request) {
	requestID := httpx.RequestID(request)
	if h.healthCheck != nil {
		ctx, cancel := context.WithTimeout(request.Context(), 200*time.Millisecond)
		defer cancel()
		if err := h.healthCheck(ctx); err != nil {
			httpx.JSON(w, http.StatusServiceUnavailable, map[string]any{"status": "degraded", "requestId": requestID})
			return
		}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"status": "ok", "requestId": requestID})
}

func (h *Handler) metricsEndpoint(w http.ResponseWriter, request *http.Request) {
	if _, ok := h.adminIdentity(w, request); !ok {
		return
	}
	if h.metrics == nil {
		h.metrics = observability.NewMetrics()
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := h.metrics.WritePrometheus(w); err != nil {
		// The response may already contain a partial exposition. Do not expose
		// the underlying writer or storage error to the client.
		return
	}
}

func (h *Handler) plans(w http.ResponseWriter, request *http.Request) {
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "plans": credits.PlanCatalog()})
}

func (h *Handler) adminRates(w http.ResponseWriter, request *http.Request) {
	if _, ok := h.adminIdentity(w, request); !ok {
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "ratePolicy": h.service.RatePolicy()})
}

func (h *Handler) updateAdminRates(w http.ResponseWriter, request *http.Request) {
	if _, ok := h.adminIdentity(w, request); !ok {
		return
	}
	var policy credits.RatePolicy
	if !h.decodeJSON(w, request, &policy) {
		return
	}
	if err := policy.Validate(); err != nil {
		httpx.Error(w, http.StatusBadRequest, httpx.RequestID(request), contract.ErrInvalidRequest, err.Error(), false)
		return
	}
	if h.saveRatePolicy != nil {
		if err := h.saveRatePolicy(request.Context(), policy); err != nil {
			httpx.Error(w, http.StatusServiceUnavailable, httpx.RequestID(request), contract.ErrProviderUnavailable, "rate policy could not be saved", true)
			return
		}
	}
	if err := h.service.SetRatePolicy(policy); err != nil {
		httpx.Error(w, http.StatusBadRequest, httpx.RequestID(request), contract.ErrInvalidRequest, err.Error(), false)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "ratePolicy": h.service.RatePolicy()})
}

func (h *Handler) account(w http.ResponseWriter, request *http.Request) {
	identity, ok := h.identity(w, request)
	if !ok {
		return
	}
	if h.billing != nil {
		if err := h.billing.SyncPlan(request.Context(), identity.UserID); err != nil {
			h.billingError(w, request, err)
			return
		}
		subscription, err := h.billing.Account(request.Context(), identity.UserID)
		if err != nil {
			h.billingError(w, request, err)
			return
		}
		plan, status, err := h.billing.Plan(request.Context(), identity.UserID)
		if err != nil {
			h.billingError(w, request, err)
			return
		}
		var deletion *account.Deletion
		if h.accountService != nil {
			deletion, _ = h.accountService.Deletion(request.Context(), identity.UserID)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "account": contract.Account{UserID: identity.UserID, Plan: plan, Subscription: status, CurrentPeriodEnd: timePtr(subscription.CurrentPeriodEnd), GraceUntil: subscription.GraceUntil, CancelAtPeriodEnd: subscription.CancelAtPeriodEnd, BillingConfigured: h.billing.Configured()}, "deletion": deletion})
		return
	}
	plan := h.ledger.Plan(identity.UserID)
	var deletion *account.Deletion
	if h.accountService != nil {
		deletion, _ = h.accountService.Deletion(request.Context(), identity.UserID)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "account": contract.Account{UserID: identity.UserID, Plan: plan, Subscription: "active"}, "deletion": deletion})
}

type recentAuthentication interface {
	RecentlyAuthenticated(*http.Request, time.Duration) bool
}

func (h *Handler) requestAccountDeletion(w http.ResponseWriter, request *http.Request) {
	identity, ok := h.identity(w, request)
	if !ok {
		return
	}
	checker, ok := h.auth.(recentAuthentication)
	if !ok || !checker.RecentlyAuthenticated(request, 15*time.Minute) {
		httpx.Error(w, http.StatusForbidden, httpx.RequestID(request), contract.ErrForbidden, "recent re-authentication is required before deleting the account", false)
		return
	}
	if h.accountService == nil {
		httpx.Error(w, http.StatusServiceUnavailable, httpx.RequestID(request), contract.ErrProviderUnavailable, "account deletion is temporarily unavailable", true)
		return
	}
	deletion, err := h.accountService.RequestDeletion(request.Context(), identity.UserID)
	if err != nil {
		h.accountError(w, request, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "deletion": deletion})
}

func (h *Handler) cancelAccountDeletion(w http.ResponseWriter, request *http.Request) {
	identity, ok := h.identity(w, request)
	if !ok {
		return
	}
	if h.accountService == nil {
		httpx.Error(w, http.StatusServiceUnavailable, httpx.RequestID(request), contract.ErrProviderUnavailable, "account deletion is temporarily unavailable", true)
		return
	}
	if err := h.accountService.CancelDeletion(request.Context(), identity.UserID); err != nil {
		h.accountError(w, request, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "canceled": true})
}

func (h *Handler) accountError(w http.ResponseWriter, request *http.Request, err error) {
	status, code, message := http.StatusServiceUnavailable, contract.ErrProviderUnavailable, "account service is temporarily unavailable"
	if errors.Is(err, account.ErrAlreadyDeleted) {
		status, code, message = http.StatusForbidden, contract.ErrForbidden, "account is no longer available"
	} else if errors.Is(err, account.ErrNotFound) {
		status, code, message = http.StatusNotFound, contract.ErrInvalidRequest, "account not found"
	}
	httpx.Error(w, status, httpx.RequestID(request), code, message, status >= 500)
}

func timePtr(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}

func (h *Handler) billingInfo(w http.ResponseWriter, request *http.Request) {
	identity, ok := h.identity(w, request)
	if !ok {
		return
	}
	if h.billing == nil {
		httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "configured": false, "subscription": nil})
		return
	}
	subscription, err := h.billing.Account(request.Context(), identity.UserID)
	if err != nil {
		h.billingError(w, request, err)
		return
	}
	plan, status, err := h.billing.Plan(request.Context(), identity.UserID)
	if err != nil {
		h.billingError(w, request, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "configured": h.billing.Configured(), "plan": plan, "subscriptionStatus": status, "subscription": subscription})
}

func (h *Handler) checkout(w http.ResponseWriter, request *http.Request) {
	identity, ok := h.identity(w, request)
	if !ok {
		return
	}
	if h.billing == nil {
		h.billingError(w, request, billing.ErrNotConfigured)
		return
	}
	var payload struct {
		PlanID string `json:"planId"`
	}
	if !h.decodeJSON(w, request, &payload) {
		return
	}
	session, err := h.billing.Checkout(request.Context(), identity.UserID, strings.TrimSpace(payload.PlanID))
	if err != nil {
		h.billingError(w, request, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "checkout": session})
}

func (h *Handler) portal(w http.ResponseWriter, request *http.Request) {
	identity, ok := h.identity(w, request)
	if !ok {
		return
	}
	if h.billing == nil {
		h.billingError(w, request, billing.ErrNotConfigured)
		return
	}
	portalURL, err := h.billing.Portal(request.Context(), identity.UserID)
	if err != nil {
		h.billingError(w, request, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "url": portalURL})
}

func (h *Handler) changePlan(w http.ResponseWriter, request *http.Request) {
	identity, ok := h.identity(w, request)
	if !ok {
		return
	}
	if h.billing == nil {
		h.billingError(w, request, billing.ErrNotConfigured)
		return
	}
	var payload struct {
		PlanID string `json:"planId"`
	}
	if !h.decodeJSON(w, request, &payload) {
		return
	}
	subscription, err := h.billing.ChangePlan(request.Context(), identity.UserID, strings.TrimSpace(payload.PlanID))
	if err != nil {
		h.billingError(w, request, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "subscription": subscription})
}

func (h *Handler) stripeWebhook(w http.ResponseWriter, request *http.Request) {
	if h.billing == nil {
		h.billingError(w, request, billing.ErrNotConfigured)
		return
	}
	request.Body = http.MaxBytesReader(w, request.Body, 2<<20)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			httpx.Error(w, http.StatusRequestEntityTooLarge, httpx.RequestID(request), contract.ErrRequestTooLarge, "webhook body is too large", false)
			return
		}
		h.billingError(w, request, billing.ErrInvalidEvent)
		return
	}
	if err := h.billing.HandleWebhook(request.Context(), body, request.Header.Get("Stripe-Signature")); err != nil {
		h.billingError(w, request, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "received": true})
}

func (h *Handler) billingError(w http.ResponseWriter, request *http.Request, err error) {
	status := http.StatusServiceUnavailable
	code := contract.ErrProviderUnavailable
	message := "billing is temporarily unavailable"
	if errors.Is(err, billing.ErrInvalidPlan) || errors.Is(err, billing.ErrInvalidEvent) {
		status, code, message = http.StatusBadRequest, contract.ErrInvalidRequest, "invalid billing request"
	} else if errors.Is(err, billing.ErrPlanChange) {
		status, code, message = http.StatusConflict, contract.ErrInvalidRequest, "this plan change must be completed through an active subscription"
	} else if errors.Is(err, billing.ErrNotFound) {
		status, code, message = http.StatusNotFound, contract.ErrInvalidRequest, "billing record not found"
	}
	httpx.Error(w, status, httpx.RequestID(request), code, message, status >= 500)
}

func (h *Handler) credits(w http.ResponseWriter, request *http.Request) {
	identity, ok := h.identity(w, request)
	if !ok {
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "credits": h.ledger.Balance(identity.UserID)})
}

func (h *Handler) usage(w http.ResponseWriter, request *http.Request) {
	identity, ok := h.identity(w, request)
	if !ok {
		return
	}
	entries := h.ledger.Entries(identity.UserID)
	var consumed, reserved int64
	for _, entry := range entries {
		switch entry.Type {
		case credits.Consume:
			consumed += entry.Amount
			reserved -= entry.Amount
		case credits.Reserve:
			reserved += entry.Amount
		case credits.Release:
			reserved -= entry.Amount
		}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "usage": map[string]any{"creditsConsumed": consumed, "creditsReserved": maxInt64(0, reserved)}})
}

func (h *Handler) estimate(w http.ResponseWriter, request *http.Request) {
	identity, ok := h.identity(w, request)
	if !ok {
		return
	}
	var payload contract.TranslationRequest
	if !h.decodeJSON(w, request, &payload) {
		return
	}
	estimate, err := h.service.Estimate(identity.UserID, payload)
	if err != nil {
		h.writeServiceError(w, request, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "estimate": estimate})
}

func (h *Handler) startTranslation(w http.ResponseWriter, request *http.Request) {
	identity, ok := h.identity(w, request)
	if !ok {
		return
	}
	idempotencyKey := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	var payload contract.TranslationRequest
	if !h.decodeJSON(w, request, &payload) {
		return
	}
	if strings.Contains(request.Header.Get("Accept"), "text/event-stream") {
		h.streamTranslationRequest(w, request, identity.UserID, idempotencyKey, payload)
		return
	}
	resource, err := h.service.Start(request.Context(), identity.UserID, idempotencyKey, payload)
	if err != nil {
		h.writeServiceError(w, request, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "translation": resource})
}

// streamTranslationRequest opens the SSE response before calling the
// provider. The request context is deliberately passed into the goroutine so
// a browser navigation or network disconnect cancels the provider job and
// causes the service to release its reservation.
func (h *Handler) streamTranslationRequest(w http.ResponseWriter, request *http.Request, userID, idempotencyKey string, payload contract.TranslationRequest) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.writeServiceError(w, request, &translation.RequestError{Code: contract.ErrTranslationFailed, Message: "streaming is unavailable", Retryable: false})
		return
	}
	type outcome struct {
		resource *contract.TranslationResource
		err      error
	}
	result := make(chan outcome, 1)
	started := make(chan string, 1)
	segments := make(chan contract.TranslatedSegment, 32)
	go func() {
		resource, err := h.service.StartWithEvents(request.Context(), userID, idempotencyKey, payload, func(id string) { started <- id }, func(segment contract.TranslatedSegment) error {
			select {
			case segments <- segment:
				return nil
			case <-request.Context().Done():
				return request.Context().Err()
			}
		})
		result <- outcome{resource: resource, err: err}
	}()
	startedSent := false
	emittedSegments := 0
	pendingSegments := make([]contract.TranslatedSegment, 0)
	emittedIDs := make(map[string]bool)
	for {
		select {
		case <-request.Context().Done():
			return
		case id := <-started:
			if !startedSent {
				writeSSE(w, "started", map[string]any{"requestId": httpx.RequestID(request), "translationId": id, "status": contract.StatusRunning})
				flusher.Flush()
				startedSent = true
				for _, pending := range pendingSegments {
					if emittedIDs[pending.ID] {
						continue
					}
					pending.Sequence = emittedSegments + 1
					writeSSE(w, "segment", pending)
					emittedSegments++
					emittedIDs[pending.ID] = true
				}
				pendingSegments = nil
				flusher.Flush()
			}
		case segment := <-segments:
			if !startedSent {
				pendingSegments = append(pendingSegments, segment)
				continue
			}
			if emittedIDs[segment.ID] {
				continue
			}
			segment.Sequence = emittedSegments + 1
			writeSSE(w, "segment", segment)
			emittedSegments++
			emittedIDs[segment.ID] = true
			flusher.Flush()
		case completed := <-result:
			if completed.err != nil {
				code, message, retryable := contract.ErrTranslationFailed, "translation failed", false
				var typed *translation.RequestError
				if errors.As(completed.err, &typed) {
					code, message, retryable = typed.Code, typed.Message, typed.Retryable
				}
				writeSSE(w, "failed", contract.APIError{Code: code, Message: message, RequestID: httpx.RequestID(request), Retryable: retryable})
				flusher.Flush()
				return
			}
			if !startedSent {
				writeSSE(w, "started", map[string]any{"requestId": httpx.RequestID(request), "translationId": completed.resource.ID, "status": completed.resource.Status})
				flusher.Flush()
			}
			if completed.resource.Result != nil {
				// Streaming providers have already emitted each segment. The
				// final result is still sent for clients that reconcile local state.
				if emittedSegments == 0 && len(completed.resource.Result.Segments) > 0 {
					for _, segment := range completed.resource.Result.Segments {
						if emittedIDs[segment.ID] {
							continue
						}
						segment.Sequence = emittedSegments + 1
						writeSSE(w, "segment", segment)
						emittedSegments++
						emittedIDs[segment.ID] = true
					}
				}
				writeSSE(w, "usage", completed.resource.Result.Usage)
				flusher.Flush()
			}
			writeSSE(w, "completed", completed.resource)
			flusher.Flush()
			return
		}
	}
}

func (h *Handler) streamTranslationEvents(w http.ResponseWriter, flusher http.Flusher, request *http.Request, resource *contract.TranslationResource) {
	if resource.Result == nil {
		writeSSE(w, "failed", contract.APIError{Code: resource.ErrorCode, Message: "translation failed", RequestID: httpx.RequestID(request), Retryable: false})
		flusher.Flush()
		return
	}
	for sequence, segment := range resource.Result.Segments {
		segment.Sequence = sequence + 1
		writeSSE(w, "segment", segment)
		flusher.Flush()
	}
	writeSSE(w, "usage", resource.Result.Usage)
	flusher.Flush()
	writeSSE(w, "completed", resource)
	flusher.Flush()
}

func (h *Handler) streamError(w http.ResponseWriter, request *http.Request, err error) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.writeServiceError(w, request, err)
		return
	}
	code, message, retryable := contract.ErrTranslationFailed, "translation failed", false
	var typed *translation.RequestError
	if errors.As(err, &typed) {
		code, message, retryable = typed.Code, typed.Message, typed.Retryable
	}
	writeSSE(w, "failed", contract.APIError{Code: code, Message: message, RequestID: httpx.RequestID(request), Retryable: retryable})
	flusher.Flush()
}

func writeSSE(w http.ResponseWriter, event string, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_, _ = w.Write([]byte("event: " + event + "\ndata: " + string(data) + "\n\n"))
}

func (h *Handler) getTranslation(w http.ResponseWriter, request *http.Request) {
	identity, ok := h.identity(w, request)
	if !ok {
		return
	}
	resource, err := h.service.Get(identity.UserID, request.PathValue("id"))
	if errors.Is(err, translation.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, httpx.RequestID(request), contract.ErrInvalidRequest, "translation not found", false)
		return
	}
	if err != nil {
		h.writeServiceError(w, request, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "translation": resource})
}

func (h *Handler) cancelTranslation(w http.ResponseWriter, request *http.Request) {
	identity, ok := h.identity(w, request)
	if !ok {
		return
	}
	resource, err := h.service.Cancel(identity.UserID, request.PathValue("id"))
	if errors.Is(err, translation.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, httpx.RequestID(request), contract.ErrInvalidRequest, "translation not found", false)
		return
	}
	if err != nil {
		h.writeServiceError(w, request, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"requestId": httpx.RequestID(request), "translation": resource})
}

func (h *Handler) identity(w http.ResponseWriter, request *http.Request) (auth.Identity, bool) {
	identity, ok := h.auth.Authenticate(request)
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, httpx.RequestID(request), contract.ErrUnauthorized, "authentication is required", false)
		return auth.Identity{}, false
	}
	w.Header().Set("Cache-Control", "no-store")
	if h.accountService != nil {
		deleted, err := h.accountService.ProcessDue(request.Context(), identity.UserID)
		if err != nil {
			h.accountError(w, request, err)
			return auth.Identity{}, false
		}
		active, err := h.accountService.IsActive(request.Context(), identity.UserID)
		if err != nil {
			h.accountError(w, request, err)
			return auth.Identity{}, false
		}
		if deleted || !active {
			httpx.Error(w, http.StatusUnauthorized, httpx.RequestID(request), contract.ErrUnauthorized, "authentication is required", false)
			return auth.Identity{}, false
		}
	}
	// Synchronize the effective subscription before creating a grant. In local
	// mode this also carries the Stripe-like billing period into the ledger;
	// production Postgres derives the same period from subscriptions.
	if h.billing != nil {
		if err := h.billing.SyncPlan(request.Context(), identity.UserID); err != nil {
			h.billingError(w, request, err)
			return auth.Identity{}, false
		}
	}
	// Provision the server-side user and first append-only grant after the
	// subscription state is known. subscriptions still has a foreign key to
	// users, so EnsureGrant remains the provisioning boundary.
	h.ledger.EnsureGrant(identity.UserID)
	if refresher, ok := h.auth.(sessionRefresher); ok {
		refresher.RefreshSessionCookie(w, request)
	}
	return identity, true
}

func (h *Handler) adminIdentity(w http.ResponseWriter, request *http.Request) (auth.Identity, bool) {
	identity, ok := h.identity(w, request)
	if !ok {
		return auth.Identity{}, false
	}
	for _, adminID := range h.config.AdminUserIDs {
		if strings.TrimSpace(adminID) == identity.UserID {
			return identity, true
		}
	}
	httpx.Error(w, http.StatusForbidden, httpx.RequestID(request), contract.ErrForbidden, "administrator access is required", false)
	return auth.Identity{}, false
}

func (h *Handler) decodeJSON(w http.ResponseWriter, request *http.Request, destination any) bool {
	if !strings.Contains(request.Header.Get("Content-Type"), "application/json") {
		httpx.Error(w, http.StatusBadRequest, httpx.RequestID(request), contract.ErrInvalidRequest, "Content-Type must be application/json", false)
		return false
	}
	request.Body = http.MaxBytesReader(w, request.Body, 8<<20)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			httpx.Error(w, http.StatusRequestEntityTooLarge, httpx.RequestID(request), contract.ErrRequestTooLarge, "request body is too large", false)
			return false
		}
		httpx.Error(w, http.StatusBadRequest, httpx.RequestID(request), contract.ErrInvalidRequest, "invalid JSON request", false)
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		httpx.Error(w, http.StatusBadRequest, httpx.RequestID(request), contract.ErrInvalidRequest, "request body must contain one JSON value", false)
		return false
	}
	return true
}

func (h *Handler) writeServiceError(w http.ResponseWriter, request *http.Request, err error) {
	requestID := httpx.RequestID(request)
	code := contract.ErrTranslationFailed
	message := "translation failed"
	retryable := false
	status := http.StatusInternalServerError
	var requestErr *translation.RequestError
	if errors.As(err, &requestErr) {
		code, message, retryable = requestErr.Code, requestErr.Message, requestErr.Retryable
		status = requestErr.HTTPStatus
		if status == 0 {
			status = statusForCode(code)
		}
	} else if errors.Is(err, credits.ErrInsufficient) {
		code, message, status = contract.ErrInsufficientCredits, "not enough credits", http.StatusForbidden
	} else if err != nil && h.config.AppEnv != "production" {
		message = err.Error()
	}
	httpx.Error(w, status, requestID, code, message, retryable)
}

func statusForCode(code contract.APIErrorCode) int {
	switch code {
	case contract.ErrUnauthorized:
		return http.StatusUnauthorized
	case contract.ErrForbidden:
		return http.StatusForbidden
	case contract.ErrInsufficientCredits:
		return http.StatusForbidden
	case contract.ErrRateLimited:
		return http.StatusTooManyRequests
	case contract.ErrRequestTooLarge:
		return http.StatusRequestEntityTooLarge
	case contract.ErrProviderUnavailable:
		return http.StatusBadGateway
	case contract.ErrIdempotencyConflict:
		return http.StatusConflict
	case contract.ErrInvalidRequest:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

func (h *Handler) withRequestContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requestID := httpx.NewRequestID()
		request = request.WithContext(context.WithValue(request.Context(), requestContextKey{}, requestID))
		// Keep the generated ID available to the existing response helpers, but
		// never trust a client-supplied X-Request-ID as the response identity.
		request.Header = request.Header.Clone()
		request.Header.Set("X-Request-ID", requestID)
		next.ServeHTTP(w, request)
	})
}

type metricsResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *metricsResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *metricsResponseWriter) Write(payload []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(payload)
}

func (w *metricsResponseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *metricsResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (h *Handler) withMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		started := time.Now()
		wrapped := &metricsResponseWriter{ResponseWriter: w}
		next.ServeHTTP(wrapped, request)
		status := wrapped.status
		if status == 0 {
			status = http.StatusOK
		}
		route := request.Pattern
		if route == "" {
			route = "unmatched"
		}
		if h.metrics != nil {
			h.metrics.ObserveRequest(request.Method, route, status, time.Since(started))
		}
	})
}

func (h *Handler) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		origin := request.Header.Get("Origin")
		if h.allowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Vary", "Origin")
		}
		if request.Method == http.MethodOptions {
			if origin != "" && !h.allowedOrigin(origin) {
				httpx.Error(w, http.StatusForbidden, httpx.RequestID(request), contract.ErrForbidden, "origin is not allowed", false)
				return
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Idempotency-Key, X-Request-ID")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if (request.Method == http.MethodPost || request.Method == http.MethodPut || request.Method == http.MethodDelete) && origin != "" && !h.allowedOrigin(origin) {
			if request.URL.Path == "/v1/stripe/webhook" {
				next.ServeHTTP(w, request)
				return
			}
			httpx.Error(w, http.StatusForbidden, httpx.RequestID(request), contract.ErrForbidden, "origin is not allowed", false)
			return
		}
		if (request.Method == http.MethodPost || request.Method == http.MethodPut || request.Method == http.MethodDelete) && h.config.AppEnv == "production" && origin == "" && request.URL.Path != "/v1/stripe/webhook" {
			httpx.Error(w, http.StatusForbidden, httpx.RequestID(request), contract.ErrForbidden, "origin is required for state-changing requests", false)
			return
		}
		next.ServeHTTP(w, request)
	})
}

func (h *Handler) allowedOrigin(origin string) bool {
	for _, allowed := range h.config.FrontendOrigins {
		if origin != "" && origin == allowed {
			return true
		}
	}
	return false
}

type requestContextKey struct{}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
