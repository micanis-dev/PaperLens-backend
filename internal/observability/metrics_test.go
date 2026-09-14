package observability

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/micanis/paperlens/backend/internal/credits"
)

func TestMetricsExposeBoundedOperationalSignals(t *testing.T) {
	metrics := NewMetrics()
	metrics.ObserveRequest("POST", "POST /v1/translations", 429, 120*time.Millisecond)
	metrics.ObserveRequest("GET", "GET /v1/healthz", 200, 20*time.Millisecond)
	metrics.ObserveProviderLatency("managed-openai", 2*time.Second)
	metrics.ObserveTranslationFailure()
	metrics.ObserveLedgerInconsistency()
	metrics.ObserveManagedUsage("model-a", 1_000, 1_000, credits.ModelCost{InputMicroUSDPerMillion: 10_000, OutputMicroUSDPerMillion: 20_000})

	var output bytes.Buffer
	if err := metrics.WritePrometheus(&output); err != nil {
		t.Fatalf("write metrics: %v", err)
	}
	text := output.String()
	for _, want := range []string{
		`paperlens_http_requests_total{method="POST",route="POST /v1/translations",status="429"} 1`,
		`paperlens_translation_failures_total 1`,
		`paperlens_ledger_inconsistencies_total 1`,
		`paperlens_provider_latency_seconds_count{provider="managed-openai"} 1`,
		`paperlens_managed_cost_micro_usd_total{month="`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("metrics missing %q in %s", want, text)
		}
	}
	if strings.Contains(text, "user_1") || strings.Contains(text, "request_1") {
		t.Fatal("metrics should not contain user or request identifiers")
	}
}

func TestMetricsPauseManagedTranslationAfterLedgerIssue(t *testing.T) {
	metrics := NewMetrics()
	if !metrics.AllowManagedTranslation() {
		t.Fatal("managed translations should start enabled")
	}
	metrics.ObserveLedgerInconsistency()
	if metrics.AllowManagedTranslation() {
		t.Fatal("managed translations should pause after a ledger inconsistency")
	}
}
