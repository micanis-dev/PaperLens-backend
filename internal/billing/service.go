package billing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/micanis/paperlens/backend/internal/contract"
	"github.com/micanis/paperlens/backend/internal/credits"
)

var (
	ErrNotConfigured = errors.New("billing is not configured")
	ErrNotFound      = errors.New("subscription not found")
	ErrInvalidPlan   = errors.New("paid plan is invalid")
	ErrInvalidEvent  = errors.New("invalid stripe event")
	ErrPlanChange    = errors.New("plan change requires an active Stripe subscription")
)

type Subscription struct {
	ID                     string     `json:"id"`
	UserID                 string     `json:"userId"`
	Provider               string     `json:"provider"`
	ProviderCustomerID     string     `json:"providerCustomerId,omitempty"`
	ProviderSubscriptionID string     `json:"providerSubscriptionId,omitempty"`
	PlanID                 string     `json:"planId"`
	Status                 string     `json:"status"`
	CurrentPeriodStart     time.Time  `json:"currentPeriodStart"`
	CurrentPeriodEnd       time.Time  `json:"currentPeriodEnd"`
	GraceUntil             *time.Time `json:"graceUntil,omitempty"`
	CancelAtPeriodEnd      bool       `json:"cancelAtPeriodEnd"`
	UpdatedAt              time.Time  `json:"updatedAt"`
	// LastEventAt/LastEventID are provider ordering metadata. They are kept
	// out of the public response because they are implementation details.
	LastEventAt   time.Time  `json:"-"`
	LastEventID   string     `json:"-"`
	PendingPlanID string     `json:"pendingPlanId,omitempty"`
	PendingPlanAt *time.Time `json:"pendingPlanAt,omitempty"`
}

type Store interface {
	FindByUser(context.Context, string) (Subscription, error)
	FindByProviderSubscription(context.Context, string) (Subscription, error)
	FindByProviderCustomer(context.Context, string) (Subscription, error)
	Save(context.Context, Subscription) error
	WebhookProcessed(context.Context, string, string) (bool, error)
	MarkWebhookProcessed(context.Context, string, string, string, time.Time) error
}

// webhookClaimer is an optional stronger persistence contract. Stores that
// implement it can atomically reserve a webhook before applying it, which is
// required when Stripe retries the same event against multiple API instances.
// The legacy methods remain in Store so small adapters can still be used in
// tests and local development.
type webhookClaimer interface {
	ClaimWebhook(context.Context, string, string, string, time.Time) (bool, error)
	ReleaseWebhook(context.Context, string, string) error
}

type eventSaver interface {
	SaveEvent(context.Context, Subscription) (bool, error)
}

type CheckoutSession struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

type Provider interface {
	CreateCheckout(context.Context, string, string, string, string, string) (CheckoutSession, error)
	CreatePortal(context.Context, string, string) (string, error)
}

type SubscriptionChanger interface {
	ChangeSubscription(context.Context, string, string) error
}

// PeriodEndSubscriptionChanger schedules a lower plan without changing the
// user's current entitlements. A local pending-plan marker is not enough:
// Stripe must also be told what to do at the next renewal.
type PeriodEndSubscriptionChanger interface {
	ScheduleSubscriptionChange(context.Context, string, string, time.Time) error
}

type Config struct {
	SecretKey        string
	WebhookSecret    string
	APIBaseURL       string
	SuccessURL       string
	CancelURL        string
	PortalReturnURL  string
	PriceIDs         map[string]string
	WebhookTolerance time.Duration
}

func (c Config) configured() bool {
	return strings.TrimSpace(c.SecretKey) != "" && strings.TrimSpace(c.WebhookSecret) != "" && c.PriceIDs["plus"] != "" && c.PriceIDs["pro"] != "" && c.PriceIDs["ultra"] != ""
}

func (c Config) planForPrice(priceID string) (contract.Plan, bool) {
	for planID, configuredPrice := range c.PriceIDs {
		if configuredPrice == priceID {
			plan, ok := paidPlan(planID)
			return plan, ok
		}
	}
	return contract.Plan{}, false
}

func paidPlan(id string) (contract.Plan, bool) {
	plan, ok := credits.PlanByID(id)
	return plan, ok && id != "free"
}

type Service struct {
	store            Store
	provider         Provider
	config           Config
	now              func() time.Time
	planSink         func(string, string) error
	subscriptionSink func(string, Subscription) error
}

func NewService(store Store, provider Provider, config Config, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	if config.WebhookTolerance <= 0 {
		config.WebhookTolerance = 5 * time.Minute
	}
	return &Service{store: store, provider: provider, config: config, now: now}
}

// WithPlanSink keeps the credit ledger's plan snapshot aligned with the
// subscription state. The billing service remains independent of the ledger
// implementation itself.
func (s *Service) WithPlanSink(sink func(string, string) error) *Service {
	s.planSink = sink
	return s
}

// WithSubscriptionSink propagates the provider's billing-period boundaries in
// addition to the effective plan. This prevents credit grants from being
// tied to the calendar month for monthly Stripe subscriptions.
func (s *Service) WithSubscriptionSink(sink func(string, Subscription) error) *Service {
	s.subscriptionSink = sink
	return s
}

func (s *Service) syncSubscription(userID string, subscription Subscription) error {
	effective := subscription
	effective.PlanID = effectivePlanID(subscription, s.now())
	if s.subscriptionSink != nil {
		if err := s.subscriptionSink(userID, effective); err != nil {
			return err
		}
	}
	if s.planSink != nil {
		return s.planSink(userID, effective.PlanID)
	}
	return nil
}

func (s *Service) Configured() bool { return s != nil && s.config.configured() && s.provider != nil }

func (s *Service) Account(ctx context.Context, userID string) (Subscription, error) {
	if s == nil || s.store == nil {
		return Subscription{}, ErrNotFound
	}
	subscription, err := s.store.FindByUser(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Subscription{UserID: userID, PlanID: "free", Status: "active"}, nil
		}
		return Subscription{}, err
	}
	subscription.PlanID = effectivePlanID(subscription, s.now())
	return subscription, nil
}

func (s *Service) Plan(ctx context.Context, userID string) (contract.Plan, string, error) {
	subscription, err := s.Account(ctx, userID)
	if err != nil {
		return contract.Plan{}, "", err
	}
	for _, plan := range contractPlans() {
		if plan.ID == subscription.PlanID {
			return plan, subscription.Status, nil
		}
	}
	return contractPlans()[0], subscription.Status, nil
}

func (s *Service) SyncPlan(ctx context.Context, userID string) error {
	if s.planSink == nil && s.subscriptionSink == nil {
		return nil
	}
	subscription, err := s.Account(ctx, userID)
	if err != nil {
		return err
	}
	return s.syncSubscription(userID, subscription)
}

func contractPlans() []contract.Plan {
	return credits.PlanCatalog()
}

func (s *Service) Checkout(ctx context.Context, userID, planID string) (CheckoutSession, error) {
	if !s.Configured() {
		return CheckoutSession{}, ErrNotConfigured
	}
	if _, ok := paidPlan(planID); !ok || s.config.PriceIDs[planID] == "" {
		return CheckoutSession{}, ErrInvalidPlan
	}
	if current, err := s.store.FindByUser(ctx, userID); err == nil && current.ProviderSubscriptionID != "" && current.Status != "canceled" {
		// Creating a second Checkout session for an existing subscription can
		// double-charge a customer. Existing subscribers must use ChangePlan or
		// the Customer Portal.
		return CheckoutSession{}, ErrPlanChange
	}
	return s.provider.CreateCheckout(ctx, userID, planID, s.config.PriceIDs[planID], s.config.SuccessURL, s.config.CancelURL)
}

// ChangePlan keeps upgrades immediate and downgrades at the end of the
// already-paid period. The actual paid-plan mutation is confirmed by the
// subsequent Stripe webhook; this endpoint never trusts a browser claim.
func (s *Service) ChangePlan(ctx context.Context, userID, planID string) (Subscription, error) {
	_, ok := paidPlan(planID)
	if !ok && planID != "free" {
		return Subscription{}, ErrInvalidPlan
	}
	if !s.Configured() {
		return Subscription{}, ErrNotConfigured
	}
	current, err := s.store.FindByUser(ctx, userID)
	if err != nil {
		return Subscription{}, err
	}
	if current.ProviderSubscriptionID == "" {
		return Subscription{}, ErrPlanChange
	}
	if current.PlanID == planID && current.PendingPlanID == "" {
		return current, nil
	}
	if planRank(planID) > planRank(current.PlanID) {
		changer, ok := s.provider.(SubscriptionChanger)
		if !ok {
			return Subscription{}, ErrPlanChange
		}
		if err := changer.ChangeSubscription(ctx, current.ProviderSubscriptionID, s.config.PriceIDs[planID]); err != nil {
			return Subscription{}, err
		}
		current.PendingPlanID = ""
		current.PendingPlanAt = nil
		return current, nil
	}
	periodEnd := current.CurrentPeriodEnd
	if periodEnd.IsZero() {
		periodEnd = s.now().UTC().AddDate(0, 1, 0)
	}
	changer, ok := s.provider.(PeriodEndSubscriptionChanger)
	if !ok {
		return Subscription{}, ErrPlanChange
	}
	if err := changer.ScheduleSubscriptionChange(ctx, current.ProviderSubscriptionID, s.config.PriceIDs[planID], periodEnd); err != nil {
		return Subscription{}, err
	}
	current.PendingPlanID = planID
	current.PendingPlanAt = &periodEnd
	if err := s.store.Save(ctx, current); err != nil {
		return Subscription{}, err
	}
	return current, nil
}

func planRank(id string) int {
	switch id {
	case "plus":
		return 1
	case "pro":
		return 2
	case "ultra":
		return 3
	default:
		return 0
	}
}

func (s *Service) Portal(ctx context.Context, userID string) (string, error) {
	if !s.Configured() {
		return "", ErrNotConfigured
	}
	subscription, err := s.store.FindByUser(ctx, userID)
	if err != nil {
		return "", err
	}
	if subscription.ProviderCustomerID == "" {
		return "", ErrNotFound
	}
	return s.provider.CreatePortal(ctx, subscription.ProviderCustomerID, s.config.PortalReturnURL)
}

type stripeEvent struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Created int64           `json:"created"`
	Data    json.RawMessage `json:"data"`
}

func (s *Service) HandleWebhook(ctx context.Context, body []byte, signature string) error {
	if s == nil || strings.TrimSpace(s.config.WebhookSecret) == "" || s.store == nil {
		return ErrNotConfigured
	}
	if !VerifySignature(body, signature, s.config.WebhookSecret, s.now(), s.config.WebhookTolerance) {
		return ErrInvalidEvent
	}
	var event stripeEvent
	if err := json.Unmarshal(body, &event); err != nil || event.ID == "" || event.Type == "" {
		return ErrInvalidEvent
	}
	claimer, atomic := s.store.(webhookClaimer)
	if atomic {
		claimed, err := claimer.ClaimWebhook(ctx, "stripe", event.ID, event.Type, s.now())
		if err != nil {
			return err
		}
		if !claimed {
			return nil
		}
		defer func() {
			// A failed application must be retryable. Successful processing is
			// marked below; release is a no-op after that mark.
			// The deferred call intentionally ignores errors because the original
			// webhook error is more useful to Stripe's retry mechanism.
			_ = claimer.ReleaseWebhook(ctx, "stripe", event.ID)
		}()
	} else {
		processed, err := s.store.WebhookProcessed(ctx, "stripe", event.ID)
		if err != nil {
			return err
		}
		if processed {
			return nil
		}
	}
	if err := s.applyEvent(ctx, event); err != nil {
		return err
	}
	if err := s.store.MarkWebhookProcessed(ctx, "stripe", event.ID, event.Type, s.now()); err != nil {
		return err
	}
	return nil
}

func (s *Service) applyEvent(ctx context.Context, event stripeEvent) error {
	switch event.Type {
	case "checkout.session.completed", "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted", "invoice.payment_failed", "invoice.payment_succeeded":
	default:
		// Stripe sends many unrelated events to a shared endpoint. A validly
		// signed event that is outside this service's lifecycle is acknowledged
		// without changing account state.
		return nil
	}
	var object map[string]any
	var envelope struct {
		Object map[string]any `json:"object"`
	}
	if err := json.Unmarshal(event.Data, &envelope); err != nil {
		return ErrInvalidEvent
	}
	object = envelope.Object
	if object == nil {
		return ErrInvalidEvent
	}
	userID := stringValue(object["client_reference_id"])
	metadata, _ := object["metadata"].(map[string]any)
	if userID == "" {
		userID = stringValue(metadata["user_id"])
	}
	customerID := stringValue(object["customer"])
	subscriptionID := stringValue(object["subscription"])
	if subscriptionID == "" {
		// Subscription objects use their own id. Invoice events may omit the
		// subscription relation, in which case the customer lookup below must
		// retain the existing subscription id rather than replacing it with the
		// invoice id.
		if strings.HasPrefix(event.Type, "customer.subscription.") {
			subscriptionID = stringValue(object["id"])
		}
	}
	current, lookupErr := s.store.FindByProviderSubscription(ctx, subscriptionID)
	if userID == "" && lookupErr == nil {
		userID = current.UserID
	}
	if customerID != "" {
		if byCustomer, err := s.store.FindByProviderCustomer(ctx, customerID); err == nil {
			if userID != "" && byCustomer.UserID != userID {
				return ErrInvalidEvent
			}
			if userID == "" {
				userID = byCustomer.UserID
			}
			if current.UserID == "" {
				current = byCustomer
			}
		}
	}
	if userID == "" {
		return ErrInvalidEvent
	}
	if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
		return lookupErr
	}
	if current.UserID != "" && current.UserID != userID {
		return ErrInvalidEvent
	}
	if current.UserID == "" {
		current = Subscription{ID: "subscription:" + userID, UserID: userID, Provider: "stripe", PlanID: "free"}
	}
	// Stripe can deliver events out of order. Ignore an older event after the
	// account has accepted a newer one, while still recording the webhook as
	// processed so Stripe does not retry it forever.
	eventAt := time.Time{}
	if event.Created > 0 {
		eventAt = time.Unix(event.Created, 0).UTC()
	}
	if !eventAt.IsZero() && !current.LastEventAt.IsZero() {
		if eventAt.Before(current.LastEventAt) {
			return nil
		}
	}
	current.UserID = userID
	current.Provider = "stripe"
	if customerID != "" {
		current.ProviderCustomerID = customerID
	}
	if subscriptionID != "" {
		current.ProviderSubscriptionID = subscriptionID
	}
	if planID := s.planIDFromObject(object, metadata); planID != "" {
		current.PlanID = planID
		if current.PendingPlanID == planID {
			current.PendingPlanID = ""
			current.PendingPlanAt = nil
		}
	}
	current.Status = eventStatus(event.Type, stringValue(object["status"]), current.Status)
	if current.Status == "past_due" {
		if current.GraceUntil == nil {
			graceStart := s.now()
			if !eventAt.IsZero() {
				graceStart = eventAt
			}
			grace := graceStart.Add(7 * 24 * time.Hour)
			current.GraceUntil = &grace
		}
	} else if current.Status == "active" || current.Status == "trialing" {
		current.GraceUntil = nil
	}
	if event.Type == "customer.subscription.deleted" {
		current.CancelAtPeriodEnd = false
	}
	if value := int64Value(object["current_period_start"]); value > 0 {
		current.CurrentPeriodStart = time.Unix(value, 0).UTC()
	}
	if value := int64Value(object["current_period_end"]); value > 0 {
		current.CurrentPeriodEnd = time.Unix(value, 0).UTC()
	}
	if value, ok := object["cancel_at_period_end"].(bool); ok {
		current.CancelAtPeriodEnd = value
	}
	if current.CurrentPeriodStart.IsZero() {
		current.CurrentPeriodStart = s.now().UTC()
	}
	if current.CurrentPeriodEnd.IsZero() {
		current.CurrentPeriodEnd = current.CurrentPeriodStart.AddDate(0, 1, 0)
	}
	current.UpdatedAt = s.now().UTC()
	if !eventAt.IsZero() {
		current.LastEventAt = eventAt
	}
	current.LastEventID = event.ID
	if saver, ok := s.store.(eventSaver); ok {
		applied, err := saver.SaveEvent(ctx, current)
		if err != nil {
			return err
		}
		if !applied {
			return nil
		}
	} else if err := s.store.Save(ctx, current); err != nil {
		return err
	}
	return s.syncSubscription(userID, current)
}

func effectivePlanID(subscription Subscription, now time.Time) string {
	if subscription.PendingPlanID != "" && subscription.PendingPlanAt != nil && !now.Before(*subscription.PendingPlanAt) {
		return subscription.PendingPlanID
	}
	if subscription.Status != "active" && subscription.Status != "trialing" && subscription.Status != "past_due" && subscription.Status != "canceled" {
		return "free"
	}
	if subscription.Status == "past_due" && subscription.GraceUntil != nil && !now.Before(*subscription.GraceUntil) {
		return "free"
	}
	if subscription.Status == "canceled" && !subscription.CurrentPeriodEnd.IsZero() && !now.Before(subscription.CurrentPeriodEnd) {
		return "free"
	}
	return subscription.PlanID
}

func (s *Service) planIDFromObject(object, metadata map[string]any) string {
	items, _ := object["items"].(map[string]any)
	data, _ := items["data"].([]any)
	if len(data) == 0 {
		return stringValue(metadata["plan_id"])
	}
	first, _ := data[0].(map[string]any)
	price, _ := first["price"].(map[string]any)
	plan, ok := s.config.planForPrice(stringValue(price["id"]))
	if !ok {
		return ""
	}
	return plan.ID
}

func eventStatus(eventType, providerStatus, current string) string {
	switch eventType {
	case "customer.subscription.deleted":
		return "canceled"
	case "invoice.payment_failed":
		return "past_due"
	case "invoice.payment_succeeded":
		return "active"
	case "checkout.session.completed":
		return "active"
	}
	if providerStatus != "" {
		return providerStatus
	}
	if current != "" {
		return current
	}
	return "active"
}

func stringValue(value any) string {
	stringValue, _ := value.(string)
	return strings.TrimSpace(stringValue)
}

func int64Value(value any) int64 {
	switch number := value.(type) {
	case float64:
		return int64(number)
	case json.Number:
		parsed, _ := number.Int64()
		return parsed
	default:
		return 0
	}
}

func VerifySignature(payload []byte, header, secret string, now time.Time, tolerance time.Duration) bool {
	parts := strings.Split(header, ",")
	var timestamp string
	var signatures [][]byte
	for _, part := range parts {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch key {
		case "t":
			timestamp = value
		case "v1":
			expected, err := hex.DecodeString(value)
			if err != nil {
				continue
			}
			signatures = append(signatures, expected)
		}
	}
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || tolerance <= 0 || absDuration(now.Sub(time.Unix(seconds, 0))) > tolerance {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp + "." + string(payload)))
	for _, signature := range signatures {
		if hmac.Equal(signature, mac.Sum(nil)) {
			return true
		}
	}
	return false
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

type HTTPProvider struct {
	SecretKey string
	BaseURL   string
	Client    *http.Client
}

func (p HTTPProvider) CreateCheckout(ctx context.Context, userID, planID, priceID, successURL, cancelURL string) (CheckoutSession, error) {
	values := url.Values{}
	values.Set("mode", "subscription")
	values.Set("line_items[0][price]", priceID)
	values.Set("line_items[0][quantity]", "1")
	values.Set("client_reference_id", userID)
	values.Set("metadata[user_id]", userID)
	values.Set("metadata[plan_id]", planID)
	values.Set("success_url", successURL)
	values.Set("cancel_url", cancelURL)
	values.Set("subscription_data[metadata][user_id]", userID)
	values.Set("subscription_data[metadata][plan_id]", planID)
	body, err := p.post(ctx, "/v1/checkout/sessions", values)
	if err != nil {
		return CheckoutSession{}, err
	}
	return func(body []byte) (CheckoutSession, error) {
		var result struct {
			ID  string `json:"id"`
			URL string `json:"url"`
		}
		if err := json.Unmarshal(body, &result); err != nil || result.ID == "" || result.URL == "" {
			return CheckoutSession{}, fmt.Errorf("invalid checkout response")
		}
		return CheckoutSession{ID: result.ID, URL: result.URL}, nil
	}(body)
}

func (p HTTPProvider) CreatePortal(ctx context.Context, customerID, returnURL string) (string, error) {
	values := url.Values{"customer": {customerID}, "return_url": {returnURL}}
	body, err := p.post(ctx, "/v1/billing_portal/sessions", values)
	if err != nil {
		return "", err
	}
	return func(body []byte) (string, error) {
		var result struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(body, &result); err != nil || result.URL == "" {
			return "", fmt.Errorf("invalid portal response")
		}
		return result.URL, nil
	}(body)
}

func (p HTTPProvider) ChangeSubscription(ctx context.Context, subscriptionID, priceID string) error {
	if strings.TrimSpace(subscriptionID) == "" || strings.TrimSpace(priceID) == "" {
		return ErrInvalidPlan
	}
	body, err := p.request(ctx, http.MethodGet, "/v1/subscriptions/"+url.PathEscape(subscriptionID), nil)
	if err != nil {
		return err
	}
	var subscription struct {
		Schedule string `json:"schedule"`
		Items    struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &subscription); err != nil || len(subscription.Items.Data) == 0 || subscription.Items.Data[0].ID == "" {
		return fmt.Errorf("stripe subscription has no editable item")
	}
	if subscription.Schedule != "" {
		if _, err := p.request(ctx, http.MethodPost, "/v1/subscription_schedules/"+url.PathEscape(subscription.Schedule)+"/release", nil); err != nil {
			return err
		}
	}
	values := url.Values{"items[0][id]": {subscription.Items.Data[0].ID}, "items[0][price]": {priceID}, "proration_behavior": {"always_invoice"}, "cancel_at_period_end": {"false"}}
	_, err = p.request(ctx, http.MethodPost, "/v1/subscriptions/"+url.PathEscape(subscriptionID), values)
	return err
}

// ScheduleSubscriptionChange preserves the current Stripe subscription until
// its renewal boundary. Free is represented by cancel_at_period_end; paid
// downgrades use a subscription schedule with the current price followed by
// the requested price. Stripe owns the timing, so a process restart cannot
// turn a local-only pending plan into an incorrectly renewed subscription.
func (p HTTPProvider) ScheduleSubscriptionChange(ctx context.Context, subscriptionID, priceID string, periodEnd time.Time) error {
	if strings.TrimSpace(subscriptionID) == "" || periodEnd.IsZero() {
		return ErrInvalidPlan
	}

	if strings.TrimSpace(priceID) == "" {
		// A previous paid downgrade may already have attached a schedule. It
		// must be released before cancel_at_period_end is set, otherwise Stripe
		// can still apply that scheduled price after renewal.
		subscriptionBody, err := p.request(ctx, http.MethodGet, "/v1/subscriptions/"+url.PathEscape(subscriptionID), nil)
		if err != nil {
			return err
		}
		var subscription struct {
			Schedule string `json:"schedule"`
		}
		if err := json.Unmarshal(subscriptionBody, &subscription); err != nil {
			return fmt.Errorf("stripe returned an invalid subscription response")
		}
		if subscription.Schedule != "" {
			if _, err := p.request(ctx, http.MethodPost, "/v1/subscription_schedules/"+url.PathEscape(subscription.Schedule)+"/release", nil); err != nil {
				return err
			}
		}
		values := url.Values{"cancel_at_period_end": {"true"}}
		_, err = p.request(ctx, http.MethodPost, "/v1/subscriptions/"+url.PathEscape(subscriptionID), values)
		return err
	}

	// A schedule may already exist if the user changed plans previously. Reuse
	// it instead of creating a second schedule for the same subscription.
	subscriptionBody, err := p.request(ctx, http.MethodGet, "/v1/subscriptions/"+url.PathEscape(subscriptionID), nil)
	if err != nil {
		return err
	}
	var subscription struct {
		Schedule string `json:"schedule"`
		Items    struct {
			Data []struct {
				Price struct {
					ID string `json:"id"`
				} `json:"price"`
				Quantity int64 `json:"quantity"`
			} `json:"data"`
		} `json:"items"`
	}
	if err := json.Unmarshal(subscriptionBody, &subscription); err != nil || len(subscription.Items.Data) == 0 {
		return fmt.Errorf("stripe subscription has no schedulable item")
	}
	currentPrice := subscription.Items.Data[0].Price.ID
	quantity := subscription.Items.Data[0].Quantity
	if currentPrice == "" {
		return fmt.Errorf("stripe subscription has no current price")
	}
	if quantity < 1 {
		quantity = 1
	}

	scheduleID := subscription.Schedule
	if scheduleID == "" {
		created, createErr := p.request(ctx, http.MethodPost, "/v1/subscription_schedules", url.Values{"from_subscription": {subscriptionID}})
		if createErr != nil {
			return createErr
		}
		var schedule struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(created, &schedule); err != nil || schedule.ID == "" {
			return fmt.Errorf("stripe returned an invalid subscription schedule")
		}
		scheduleID = schedule.ID
	}
	scheduleBody, err := p.request(ctx, http.MethodGet, "/v1/subscription_schedules/"+url.PathEscape(scheduleID), nil)
	if err != nil {
		return err
	}
	var schedule struct {
		Phases []struct {
			StartDate int64 `json:"start_date"`
			EndDate   int64 `json:"end_date"`
			Items     struct {
				Data []struct {
					Price struct {
						ID string `json:"id"`
					} `json:"price"`
					Quantity int64 `json:"quantity"`
				} `json:"data"`
			} `json:"items"`
		} `json:"phases"`
	}
	if err := json.Unmarshal(scheduleBody, &schedule); err != nil {
		return fmt.Errorf("stripe returned an invalid subscription schedule")
	}
	currentStart := int64(0)
	for _, phase := range schedule.Phases {
		if phase.StartDate <= time.Now().UTC().Unix() && (phase.EndDate == 0 || time.Now().UTC().Unix() < phase.EndDate) {
			currentStart = phase.StartDate
			break
		}
	}
	if currentStart == 0 {
		currentStart = time.Now().UTC().Unix()
	}

	// The schedule is intentionally rewritten with the current phase and one
	// future phase. Past phases are omitted as permitted by Stripe's schedule
	// API, and the current phase is retained so entitlements do not change now.
	values := url.Values{}
	values.Set("end_behavior", "release")
	values.Set("proration_behavior", "none")
	values.Set("phases[0][start_date]", strconv.FormatInt(currentStart, 10))
	values.Set("phases[0][end_date]", strconv.FormatInt(periodEnd.UTC().Unix(), 10))
	values.Set("phases[0][items][0][price]", currentPrice)
	values.Set("phases[0][items][0][quantity]", strconv.FormatInt(quantity, 10))
	values.Set("phases[0][proration_behavior]", "none")
	values.Set("phases[1][start_date]", strconv.FormatInt(periodEnd.UTC().Unix(), 10))
	values.Set("phases[1][items][0][price]", priceID)
	values.Set("phases[1][items][0][quantity]", strconv.FormatInt(quantity, 10))
	values.Set("phases[1][proration_behavior]", "none")
	_, err = p.request(ctx, http.MethodPost, "/v1/subscription_schedules/"+url.PathEscape(scheduleID), values)
	return err
}

func (p HTTPProvider) post(ctx context.Context, path string, values url.Values) ([]byte, error) {
	return p.request(ctx, http.MethodPost, path, values)
}

func (p HTTPProvider) request(ctx context.Context, method, path string, values url.Values) ([]byte, error) {
	base := strings.TrimRight(p.BaseURL, "/")
	if base == "" {
		base = "https://api.stripe.com"
	}
	var requestBody io.Reader
	if values != nil {
		requestBody = strings.NewReader(values.Encode())
	}
	request, err := http.NewRequestWithContext(ctx, method, base+path, requestBody)
	if err != nil {
		return nil, err
	}
	if values != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	request.SetBasicAuth(p.SecretKey, "")
	client := p.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("stripe request failed with status %d", response.StatusCode)
	}
	return body, nil
}

type MemoryStore struct {
	mu       sync.Mutex
	items    map[string]Subscription
	webhooks map[string]memoryWebhook
}

type memoryWebhook struct {
	processingAt time.Time
	processedAt  time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{items: make(map[string]Subscription), webhooks: make(map[string]memoryWebhook)}
}

func (s *MemoryStore) FindByUser(_ context.Context, userID string) (Subscription, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.items {
		if item.UserID == userID {
			return item, nil
		}
	}
	return Subscription{}, ErrNotFound
}

func (s *MemoryStore) FindByProviderSubscription(_ context.Context, id string) (Subscription, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.items {
		if id != "" && item.ProviderSubscriptionID == id {
			return item, nil
		}
	}
	return Subscription{}, ErrNotFound
}

func (s *MemoryStore) FindByProviderCustomer(_ context.Context, id string) (Subscription, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.items {
		if id != "" && item.ProviderCustomerID == id {
			return item, nil
		}
	}
	return Subscription{}, ErrNotFound
}

func (s *MemoryStore) Save(_ context.Context, subscription Subscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if subscription.ID == "" {
		subscription.ID = "subscription:" + subscription.UserID
	}
	s.items[subscription.ID] = subscription
	return nil
}

func (s *MemoryStore) SaveEvent(_ context.Context, subscription Subscription) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if subscription.ID == "" {
		subscription.ID = "subscription:" + subscription.UserID
	}
	if current, exists := s.items[subscription.ID]; exists && !subscription.LastEventAt.IsZero() && !current.LastEventAt.IsZero() && subscription.LastEventAt.Before(current.LastEventAt) {
		return false, nil
	}
	s.items[subscription.ID] = subscription
	return true, nil
}

func (s *MemoryStore) WebhookProcessed(_ context.Context, provider, eventID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := provider + ":" + eventID
	item, exists := s.webhooks[key]
	return exists && !item.processedAt.IsZero(), nil
}

func (s *MemoryStore) MarkWebhookProcessed(_ context.Context, provider, eventID, _ string, processedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := provider + ":" + eventID
	item := s.webhooks[key]
	item.processingAt = time.Time{}
	item.processedAt = processedAt
	s.webhooks[key] = item
	return nil
}

func (s *MemoryStore) ClaimWebhook(_ context.Context, provider, eventID, _ string, claimedAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := provider + ":" + eventID
	item, exists := s.webhooks[key]
	if exists && !item.processedAt.IsZero() {
		return false, nil
	}
	if exists && !item.processingAt.IsZero() && claimedAt.Sub(item.processingAt) < 5*time.Minute {
		return false, nil
	}
	item.processingAt = claimedAt
	s.webhooks[key] = item
	return true, nil
}

func (s *MemoryStore) ReleaseWebhook(_ context.Context, provider, eventID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := provider + ":" + eventID
	item := s.webhooks[key]
	if item.processedAt.IsZero() {
		delete(s.webhooks, key)
	}
	return nil
}
