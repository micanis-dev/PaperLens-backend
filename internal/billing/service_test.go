package billing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type testProvider struct{}

func (testProvider) CreateCheckout(context.Context, string, string, string, string, string) (CheckoutSession, error) {
	return CheckoutSession{ID: "cs_test", URL: "https://checkout.test/cs_test"}, nil
}
func (testProvider) CreatePortal(context.Context, string, string) (string, error) {
	return "https://billing.test/session", nil
}
func (testProvider) ScheduleSubscriptionChange(context.Context, string, string, time.Time) error {
	return nil
}

type changingProvider struct {
	testProvider
	changed bool
}

func (p *changingProvider) ChangeSubscription(context.Context, string, string) error {
	p.changed = true
	return nil
}

func testConfig() Config {
	return Config{SecretKey: "sk_test", WebhookSecret: "whsec_test", PriceIDs: map[string]string{"plus": "price_plus", "pro": "price_pro", "ultra": "price_ultra"}, WebhookTolerance: 5 * time.Minute}
}

func signEvent(body []byte, timestamp int64, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(fmt.Sprintf("%d.%s", timestamp, body)))
	return fmt.Sprintf("v1=%s,t=%d", hex.EncodeToString(mac.Sum(nil)), timestamp)
}

func TestVerifySignatureAcceptsHeaderFieldOrder(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	body := []byte(`{"id":"evt_1"}`)
	if !VerifySignature(body, signEvent(body, now.Unix(), "secret"), "secret", now, time.Minute) {
		t.Fatal("expected valid Stripe signature")
	}
	if VerifySignature(body, signEvent(body, now.Add(-2*time.Minute).Unix(), "secret"), "secret", now, time.Minute) {
		t.Fatal("expected expired Stripe signature to be rejected")
	}
}

func TestWebhookIsAppliedOnceAndSyncsPlan(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := NewMemoryStore()
	var synced string
	service := NewService(store, testProvider{}, testConfig(), func() time.Time { return now }).WithPlanSink(func(_, plan string) error { synced = plan; return nil })
	body := []byte(`{"id":"evt_subscription_1","type":"customer.subscription.updated","created":1700000000,"data":{"object":{"id":"sub_1","customer":"cus_1","status":"active","metadata":{"user_id":"user_1"},"items":{"data":[{"price":{"id":"price_pro"}}]},"current_period_start":1699920000,"current_period_end":1702512000}}}`)
	signature := signEvent(body, now.Unix(), "whsec_test")
	if err := service.HandleWebhook(context.Background(), body, signature); err != nil {
		t.Fatalf("HandleWebhook() error = %v", err)
	}
	if synced != "pro" {
		t.Fatalf("synced plan = %q, want pro", synced)
	}
	if err := service.HandleWebhook(context.Background(), body, signature); err != nil {
		t.Fatalf("duplicate HandleWebhook() error = %v", err)
	}
	subscription, err := store.FindByUser(context.Background(), "user_1")
	if err != nil {
		t.Fatalf("FindByUser() error = %v", err)
	}
	if subscription.PlanID != "pro" || subscription.ProviderSubscriptionID != "sub_1" {
		t.Fatalf("unexpected subscription: %+v", subscription)
	}
}

func TestSyncPlanPassesEffectiveBillingPeriodToSubscriptionSink(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := NewMemoryStore()
	periodEnd := now.Add(20 * 24 * time.Hour)
	if err := store.Save(context.Background(), Subscription{ID: "sub", UserID: "user_1", PlanID: "pro", Status: "active", CurrentPeriodStart: now.Add(-time.Hour), CurrentPeriodEnd: periodEnd}); err != nil {
		t.Fatal(err)
	}
	var received Subscription
	service := NewService(store, testProvider{}, testConfig(), func() time.Time { return now }).WithSubscriptionSink(func(_ string, subscription Subscription) error { received = subscription; return nil })
	if err := service.SyncPlan(context.Background(), "user_1"); err != nil {
		t.Fatal(err)
	}
	if received.PlanID != "pro" || !received.CurrentPeriodEnd.Equal(periodEnd) {
		t.Fatalf("received subscription = %+v", received)
	}
}

func TestPastDueGraceFallsBackToFree(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := NewMemoryStore()
	service := NewService(store, testProvider{}, testConfig(), func() time.Time { return now })
	grace := now.Add(-time.Hour)
	if err := store.Save(context.Background(), Subscription{ID: "sub", UserID: "user_1", PlanID: "pro", Status: "past_due", GraceUntil: &grace}); err != nil {
		t.Fatal(err)
	}
	plan, status, err := service.Plan(context.Background(), "user_1")
	if err != nil {
		t.Fatal(err)
	}
	if plan.ID != "free" || status != "past_due" {
		t.Fatalf("got plan=%s status=%s, want free/past_due", plan.ID, status)
	}
}

func TestOlderWebhookCannotRollBackSubscription(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := NewMemoryStore()
	service := NewService(store, testProvider{}, testConfig(), func() time.Time { return now })
	newer := []byte(`{"id":"evt_new","type":"customer.subscription.updated","created":1700000100,"data":{"object":{"id":"sub_1","customer":"cus_1","status":"active","metadata":{"user_id":"user_1"},"items":{"data":[{"price":{"id":"price_pro"}}]},"current_period_start":1699920000,"current_period_end":1702512000}}}`)
	older := []byte(`{"id":"evt_old","type":"customer.subscription.updated","created":1700000000,"data":{"object":{"id":"sub_1","customer":"cus_1","status":"canceled","metadata":{"user_id":"user_1"},"items":{"data":[{"price":{"id":"price_plus"}}]},"current_period_start":1699920000,"current_period_end":1702512000}}}`)
	if err := service.HandleWebhook(context.Background(), newer, signEvent(newer, now.Unix(), "whsec_test")); err != nil {
		t.Fatal(err)
	}
	if err := service.HandleWebhook(context.Background(), older, signEvent(older, now.Unix(), "whsec_test")); err != nil {
		t.Fatal(err)
	}
	subscription, err := store.FindByUser(context.Background(), "user_1")
	if err != nil {
		t.Fatal(err)
	}
	if subscription.PlanID != "pro" || subscription.Status != "active" {
		t.Fatalf("stale event rolled state back: %+v", subscription)
	}
}

func TestConcurrentDuplicateWebhookIsAppliedOnce(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := NewMemoryStore()
	service := NewService(store, testProvider{}, testConfig(), func() time.Time { return now })
	body := []byte(`{"id":"evt_concurrent","type":"customer.subscription.updated","created":1700000000,"data":{"object":{"id":"sub_1","customer":"cus_1","status":"active","metadata":{"user_id":"user_1"},"items":{"data":[{"price":{"id":"price_pro"}}]}}}}`)
	signature := signEvent(body, now.Unix(), "whsec_test")
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- service.HandleWebhook(context.Background(), body, signature) }()
	}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.FindByUser(context.Background(), "user_1"); err != nil {
		t.Fatalf("webhook was not applied: %v", err)
	}
}

func TestPlanChangeDoesNotCreateSecondSubscription(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := NewMemoryStore()
	periodEnd := now.Add(20 * 24 * time.Hour)
	if err := store.Save(context.Background(), Subscription{ID: "sub", UserID: "user_1", Provider: "stripe", ProviderSubscriptionID: "sub_1", PlanID: "pro", Status: "active", CurrentPeriodStart: now, CurrentPeriodEnd: periodEnd}); err != nil {
		t.Fatal(err)
	}
	service := NewService(store, testProvider{}, testConfig(), func() time.Time { return now })
	changed, err := service.ChangePlan(context.Background(), "user_1", "plus")
	if err != nil || changed.PendingPlanID != "plus" || changed.PendingPlanAt == nil || !changed.PendingPlanAt.Equal(periodEnd) {
		t.Fatalf("change=%+v err=%v", changed, err)
	}
	checkout, err := service.Checkout(context.Background(), "user_1", "ultra")
	if err != ErrPlanChange || checkout.URL != "" {
		t.Fatalf("duplicate checkout result=%+v err=%v", checkout, err)
	}
}

func TestUpgradeUsesSubscriptionMutationAndWaitsForWebhook(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := NewMemoryStore()
	if err := store.Save(context.Background(), Subscription{ID: "sub", UserID: "user_1", Provider: "stripe", ProviderSubscriptionID: "sub_1", PlanID: "plus", Status: "active", CurrentPeriodStart: now, CurrentPeriodEnd: now.Add(20 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	provider := &changingProvider{}
	service := NewService(store, provider, testConfig(), func() time.Time { return now })
	if _, err := service.ChangePlan(context.Background(), "user_1", "pro"); err != nil || !provider.changed {
		t.Fatalf("upgrade err=%v changed=%v", err, provider.changed)
	}
	current, _ := store.FindByUser(context.Background(), "user_1")
	if current.PlanID != "plus" {
		t.Fatalf("upgrade was applied before webhook: %+v", current)
	}
}

func TestHTTPProviderSchedulesPaidDowngradeAtRenewal(t *testing.T) {
	periodEnd := time.Unix(1_800_000_000, 0).UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/subscriptions/sub_1":
			_, _ = fmt.Fprint(w, `{"items":{"data":[{"price":{"id":"price_pro"},"quantity":1}]}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/subscription_schedules":
			if err := r.ParseForm(); err != nil || r.Form.Get("from_subscription") != "sub_1" {
				t.Errorf("unexpected schedule creation form: %v", r.Form)
			}
			_, _ = fmt.Fprint(w, `{"id":"sched_1"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/subscription_schedules/sched_1":
			_, _ = fmt.Fprint(w, `{"phases":[{"start_date":1790000000,"end_date":1800000000,"items":{"data":[{"price":{"id":"price_pro"},"quantity":1}]}}]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/subscription_schedules/sched_1":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("end_behavior") != "release" || r.Form.Get("proration_behavior") != "none" || r.Form.Get("phases[0][items][0][price]") != "price_pro" || r.Form.Get("phases[1][items][0][price]") != "price_plus" || r.Form.Get("phases[1][start_date]") != fmt.Sprint(periodEnd.Unix()) {
				t.Errorf("unexpected schedule update form: %v", r.Form)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	err := (HTTPProvider{SecretKey: "sk_test", BaseURL: server.URL, Client: server.Client()}).ScheduleSubscriptionChange(context.Background(), "sub_1", "price_plus", periodEnd)
	if err != nil {
		t.Fatalf("ScheduleSubscriptionChange() error = %v", err)
	}
}

func TestHTTPProviderCancelsFreeDowngradeAtRenewal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/subscriptions/sub_1" {
			_, _ = fmt.Fprint(w, `{"schedule":""}`)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/subscriptions/sub_1" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil || r.Form.Get("cancel_at_period_end") != "true" {
			t.Errorf("unexpected cancellation form: %v", r.Form)
		}
	}))
	defer server.Close()

	err := (HTTPProvider{SecretKey: "sk_test", BaseURL: server.URL, Client: server.Client()}).ScheduleSubscriptionChange(context.Background(), "sub_1", "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("ScheduleSubscriptionChange() error = %v", err)
	}
}
