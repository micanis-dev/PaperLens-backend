package api

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/micanis/paperlens/backend/internal/contract"
	"github.com/micanis/paperlens/backend/internal/httpx"
)

// fixedWindowLimiter is deliberately small and bounded. A production deploy
// can replace it with a shared limiter without changing the HTTP contract.
type fixedWindowLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	limit   int
	entries map[string]windowEntry
	now     func() time.Time
}

type windowEntry struct {
	started time.Time
	count   int
}

func newFixedWindowLimiter(limit int, window time.Duration, now func() time.Time) *fixedWindowLimiter {
	if now == nil {
		now = time.Now
	}
	return &fixedWindowLimiter{window: window, limit: limit, entries: make(map[string]windowEntry), now: now}
}

func (l *fixedWindowLimiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.entries) > 10_000 {
		for knownKey, knownEntry := range l.entries {
			if now.Sub(knownEntry.started) >= l.window {
				delete(l.entries, knownKey)
			}
		}
	}
	entry, ok := l.entries[key]
	if !ok || now.Sub(entry.started) >= l.window {
		l.entries[key] = windowEntry{started: now, count: 1}
		return true, 0
	}
	if entry.count >= l.limit {
		return false, l.window - now.Sub(entry.started)
	}
	entry.count++
	l.entries[key] = entry
	return true, 0
}

func clientKey(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if request.RemoteAddr != "" {
		return request.RemoteAddr
	}
	return "unknown"
}

func (h *Handler) withRateLimits(next http.Handler) http.Handler {
	// The limit is intentionally per client IP and separate from the user
	// concurrency limit enforced by translation.Service. Login has a tighter
	// independent window because magic-link delivery is an abuse-sensitive
	// operation.
	translationLimiter := newFixedWindowLimiter(60, time.Minute, time.Now)
	loginLimiter := newFixedWindowLimiter(10, time.Minute, time.Now)
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && (request.URL.Path == "/v1/translations" || request.URL.Path == "/v1/translations/estimate") {
			if !writeRateLimitError(w, request, translationLimiter, "request rate limit reached") {
				return
			}
		}
		if request.Method == http.MethodPost && request.URL.Path == "/v1/auth/magic-link" {
			if !writeRateLimitError(w, request, loginLimiter, "login request rate limit reached") {
				return
			}
		}
		next.ServeHTTP(w, request)
	})
}

func writeRateLimitError(w http.ResponseWriter, request *http.Request, limiter *fixedWindowLimiter, message string) bool {
	allowed, retryAfter := limiter.allow(clientKey(request))
	if allowed {
		return true
	}
	seconds := int(retryAfter / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	httpx.Error(w, http.StatusTooManyRequests, httpx.RequestID(request), contract.ErrRateLimited, message, true)
	return false
}
