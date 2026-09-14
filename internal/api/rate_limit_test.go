package api

import (
	"testing"
	"time"
)

func TestFixedWindowLimiterReturnsRetryDuration(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	limiter := newFixedWindowLimiter(1, time.Minute, func() time.Time { return now })
	if allowed, _ := limiter.allow("ip"); !allowed {
		t.Fatal("first request was rejected")
	}
	allowed, retryAfter := limiter.allow("ip")
	if allowed || retryAfter != time.Minute {
		t.Fatalf("allowed=%v retryAfter=%s, want false/1m", allowed, retryAfter)
	}
	now = now.Add(time.Minute)
	if allowed, _ := limiter.allow("ip"); !allowed {
		t.Fatal("request was not accepted after the window elapsed")
	}
}
