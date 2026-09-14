package observability

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/micanis/paperlens/backend/internal/credits"
)

// Metrics is a process-local metrics registry. It deliberately uses only
// bounded route/provider/model labels and never records user IDs, request
// bodies, API keys, or provider responses.
type Metrics struct {
	mu                    sync.RWMutex
	requests              map[requestMetric]uint64
	requestDuration       durationMetric
	translationFailures   uint64
	ledgerInconsistencies uint64
	providerLatency       map[string]*durationMetric
	managedCost           map[costMetric]int64
	admissionEvents       []admissionEvent
	admissionOpenUntil    time.Time
}

type requestMetric struct {
	method string
	route  string
	status int
}

type costMetric struct {
	month string
	model string
}

type durationMetric struct {
	buckets []uint64
	count   uint64
	sum     float64
}

type admissionEvent struct {
	at     time.Time
	failed bool
	ledger bool
}

var latencyBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120}

const maxInt64Value = int64(^uint64(0) >> 1)

func NewMetrics() *Metrics {
	return &Metrics{
		requests:        make(map[requestMetric]uint64),
		providerLatency: make(map[string]*durationMetric),
		managedCost:     make(map[costMetric]int64),
		requestDuration: newDurationMetric(),
	}
}

func newDurationMetric() durationMetric {
	return durationMetric{buckets: make([]uint64, len(latencyBuckets))}
}

func (m *Metrics) ObserveRequest(method, route string, status int, elapsed time.Duration) {
	if m == nil {
		return
	}
	method = boundedLabel(method, "unknown", 16)
	route = boundedLabel(route, "unmatched", 64)
	if status < 100 || status > 599 {
		status = 500
	}
	m.mu.Lock()
	m.requests[requestMetric{method: method, route: route, status: status}]++
	observeDuration(&m.requestDuration, elapsed)
	m.mu.Unlock()
}

func (m *Metrics) ObserveProviderLatency(provider string, elapsed time.Duration) {
	if m == nil {
		return
	}
	provider = boundedLabel(provider, "unknown", 64)
	m.mu.Lock()
	metric := m.providerLatency[provider]
	if metric == nil {
		value := newDurationMetric()
		metric = &value
		m.providerLatency[provider] = metric
	}
	observeDuration(metric, elapsed)
	m.mu.Unlock()
}

func (m *Metrics) ObserveTranslationFailure() {
	if m == nil {
		return
	}
	now := time.Now().UTC()
	m.mu.Lock()
	m.translationFailures++
	m.admissionEvents = append(m.admissionEvents, admissionEvent{at: now, failed: true})
	m.updateAdmissionLocked(now)
	m.mu.Unlock()
}

func (m *Metrics) ObserveTranslationSuccess() {
	if m == nil {
		return
	}
	now := time.Now().UTC()
	m.mu.Lock()
	m.admissionEvents = append(m.admissionEvents, admissionEvent{at: now})
	m.updateAdmissionLocked(now)
	m.mu.Unlock()
}

func (m *Metrics) ObserveLedgerInconsistency() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.ledgerInconsistencies++
	now := time.Now().UTC()
	m.admissionEvents = append(m.admissionEvents, admissionEvent{at: now, failed: true, ledger: true})
	m.updateAdmissionLocked(now)
	m.mu.Unlock()
}

// AllowManagedTranslation is a small in-process circuit breaker. It keeps
// managed-LLM failures from amplifying an outage while leaving local and BYOK
// paths untouched. A ledger inconsistency opens the breaker immediately;
// five or more recent translation outcomes open it when failures reach 50%.
func (m *Metrics) AllowManagedTranslation() bool {
	if m == nil {
		return true
	}
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateAdmissionLocked(now)
	return !now.Before(m.admissionOpenUntil)
}

func (m *Metrics) updateAdmissionLocked(now time.Time) {
	cutoff := now.Add(-5 * time.Minute)
	first := 0
	failures := 0
	ledgerIssues := 0
	for _, event := range m.admissionEvents {
		if event.at.Before(cutoff) {
			continue
		}
		m.admissionEvents[first] = event
		first++
		if event.failed {
			failures++
		}
		if event.ledger {
			ledgerIssues++
		}
	}
	m.admissionEvents = m.admissionEvents[:first]
	if ledgerIssues > 0 || (first >= 5 && failures*2 >= first) {
		m.admissionOpenUntil = now.Add(5 * time.Minute)
	}
}

// ObserveManagedUsage records estimated provider cost as integer micro-USD.
// Rounding each completed request up is conservative and avoids reporting a
// lower cost when the provider returns small token counts.
func (m *Metrics) ObserveManagedUsage(model string, inputTokens, outputTokens int64, cost credits.ModelCost) {
	if m == nil || inputTokens < 0 || outputTokens < 0 {
		return
	}
	inputCost := ceilMillionCost(inputTokens, cost.InputMicroUSDPerMillion)
	outputCost := ceilMillionCost(outputTokens, cost.OutputMicroUSDPerMillion)
	requestCost := inputCost
	if outputCost > maxInt64Value-requestCost {
		requestCost = maxInt64Value
	} else {
		requestCost += outputCost
	}
	m.mu.Lock()
	key := costMetric{month: time.Now().UTC().Format("2006-01"), model: boundedLabel(model, "unknown", 128)}
	if requestCost > maxInt64Value-m.managedCost[key] {
		m.managedCost[key] = maxInt64Value
	} else {
		m.managedCost[key] += requestCost
	}
	m.mu.Unlock()
}

func ceilMillionCost(tokens, microUSDPerMillion int64) int64 {
	if tokens == 0 || microUSDPerMillion <= 0 {
		return 0
	}
	if tokens > (maxInt64Value-999_999)/microUSDPerMillion {
		return maxInt64Value
	}
	return (tokens*microUSDPerMillion + 999_999) / 1_000_000
}

func observeDuration(metric *durationMetric, elapsed time.Duration) {
	seconds := elapsed.Seconds()
	if seconds < 0 {
		seconds = 0
	}
	metric.count++
	metric.sum += seconds
	for index, bound := range latencyBuckets {
		if seconds <= bound {
			metric.buckets[index]++
		}
	}
}

// WritePrometheus emits a stable text exposition format suitable for a
// scrape target. The caller is responsible for authentication and response
// headers.
func (m *Metrics) WritePrometheus(writer io.Writer) error {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, err := io.WriteString(writer, "# HELP paperlens_http_requests_total HTTP requests by bounded route and status.\n# TYPE paperlens_http_requests_total counter\n"); err != nil {
		return err
	}
	requestKeys := make([]requestMetric, 0, len(m.requests))
	for key := range m.requests {
		requestKeys = append(requestKeys, key)
	}
	sort.Slice(requestKeys, func(i, j int) bool {
		left, right := requestKeys[i], requestKeys[j]
		if left.route != right.route {
			return left.route < right.route
		}
		if left.method != right.method {
			return left.method < right.method
		}
		return left.status < right.status
	})
	for _, key := range requestKeys {
		if _, err := fmt.Fprintf(writer, "paperlens_http_requests_total{method=%s,route=%s,status=%s} %d\n", quote(key.method), quote(key.route), quote(strconv.Itoa(key.status)), m.requests[key]); err != nil {
			return err
		}
	}

	if err := writeDuration(writer, "paperlens_http_request_duration_seconds", "HTTP request duration", m.requestDuration, nil); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "# HELP paperlens_translation_failures_total Managed translation failures.\n# TYPE paperlens_translation_failures_total counter\npaperlens_translation_failures_total %d\n# HELP paperlens_ledger_inconsistencies_total Credit ledger finalization or release errors.\n# TYPE paperlens_ledger_inconsistencies_total counter\npaperlens_ledger_inconsistencies_total %d\n", m.translationFailures, m.ledgerInconsistencies); err != nil {
		return err
	}
	admissionOpen := 0
	if time.Now().UTC().Before(m.admissionOpenUntil) {
		admissionOpen = 1
	}
	if _, err := fmt.Fprintf(writer, "# HELP paperlens_managed_admission_open Whether new managed translations are temporarily stopped.\n# TYPE paperlens_managed_admission_open gauge\npaperlens_managed_admission_open %d\n", admissionOpen); err != nil {
		return err
	}

	if _, err := io.WriteString(writer, "# HELP paperlens_provider_latency_seconds Provider call duration by provider name.\n# TYPE paperlens_provider_latency_seconds histogram\n"); err != nil {
		return err
	}
	providers := make([]string, 0, len(m.providerLatency))
	for provider := range m.providerLatency {
		providers = append(providers, provider)
	}
	sort.Strings(providers)
	for _, provider := range providers {
		if err := writeDuration(writer, "paperlens_provider_latency_seconds", "", *m.providerLatency[provider], map[string]string{"provider": provider}); err != nil {
			return err
		}
	}

	if _, err := io.WriteString(writer, "# HELP paperlens_managed_cost_micro_usd_total Estimated managed-provider cost by month and model.\n# TYPE paperlens_managed_cost_micro_usd_total counter\n"); err != nil {
		return err
	}
	costKeys := make([]costMetric, 0, len(m.managedCost))
	for key := range m.managedCost {
		costKeys = append(costKeys, key)
	}
	sort.Slice(costKeys, func(i, j int) bool {
		if costKeys[i].month != costKeys[j].month {
			return costKeys[i].month < costKeys[j].month
		}
		return costKeys[i].model < costKeys[j].model
	})
	for _, key := range costKeys {
		if _, err := fmt.Fprintf(writer, "paperlens_managed_cost_micro_usd_total{month=%s,model=%s} %d\n", quote(key.month), quote(key.model), m.managedCost[key]); err != nil {
			return err
		}
	}
	return nil
}

func writeDuration(writer io.Writer, name, help string, metric durationMetric, labels map[string]string) error {
	if help != "" {
		if _, err := fmt.Fprintf(writer, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name); err != nil {
			return err
		}
	}
	base := ""
	if len(labels) > 0 {
		keys := make([]string, 0, len(labels))
		for key := range labels {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, key+"="+quote(labels[key]))
		}
		base = strings.Join(parts, ",")
	}
	for index, bound := range latencyBuckets {
		if base != "" {
			if _, err := fmt.Fprintf(writer, "%s_bucket{%s,le=%s} %d\n", name, base, quote(strconv.FormatFloat(bound, 'f', -1, 64)), metric.buckets[index]); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintf(writer, "%s_bucket{le=%s} %d\n", name, quote(strconv.FormatFloat(bound, 'f', -1, 64)), metric.buckets[index]); err != nil {
			return err
		}
	}
	if base != "" {
		if _, err := fmt.Fprintf(writer, "%s_bucket{%s,le=\"+Inf\"} %d\n%s_count{%s} %d\n%s_sum{%s} %f\n", name, base, metric.count, name, base, metric.count, name, base, metric.sum); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintf(writer, "%s_bucket{le=\"+Inf\"} %d\n%s_count %d\n%s_sum %f\n", name, metric.count, name, metric.count, name, metric.sum); err != nil {
		return err
	}
	return nil
}

func quote(value string) string {
	return strconv.Quote(value)
}

func boundedLabel(value, fallback string, max int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = fallback
	}
	if len(value) > max {
		value = value[:max]
	}
	return value
}
