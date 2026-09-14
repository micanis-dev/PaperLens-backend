package httpx

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/micanis/paperlens/backend/internal/contract"
)

func JSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func Error(w http.ResponseWriter, status int, requestID string, code contract.APIErrorCode, message string, retryable bool) {
	JSON(w, status, contract.APIError{Code: code, Message: message, RequestID: requestID, Retryable: retryable})
}

func RequestID(request *http.Request) string {
	if value := strings.TrimSpace(request.Header.Get("X-Request-ID")); value != "" && len(value) <= 128 {
		return value
	}
	return NewRequestID()
}

func NewRequestID() string {
	var bytes [12]byte
	if _, err := rand.Read(bytes[:]); err == nil {
		return "req_" + hex.EncodeToString(bytes[:])
	}
	return "req_" + strings.ReplaceAll(timeNow().Format("20060102T150405.000000000Z07:00"), ":", "")
}

var timeNow = func() time.Time { return time.Now().UTC() }
