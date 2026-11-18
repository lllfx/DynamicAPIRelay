// Package relayerr defines relay-generated error codes and their JSON wire format.
package relayerr

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

// Header names used to mark relay-generated responses.
const (
	HeaderError     = "X-Relay-Error"
	HeaderRequestID = "X-Relay-Request-ID"
)

// Code is a stable, machine-readable relay error code.
type Code string

const (
	TargetInvalid         Code = "TARGET_INVALID"
	RequestInvalid        Code = "REQUEST_INVALID"
	AuthFailed            Code = "AUTH_FAILED"
	TargetForbidden       Code = "TARGET_FORBIDDEN"
	MethodNotAllowed      Code = "METHOD_NOT_ALLOWED"
	RequestTooLarge       Code = "REQUEST_TOO_LARGE"
	RateLimited           Code = "RATE_LIMITED"
	ConcurrencyLimited    Code = "CONCURRENCY_LIMITED"
	UpstreamConnectFailed Code = "UPSTREAM_CONNECT_FAILED"
	UpstreamProtocolError Code = "UPSTREAM_PROTOCOL_ERROR"
	UpstreamTimeout       Code = "UPSTREAM_TIMEOUT"
	NotFound              Code = "NOT_FOUND"
	Internal              Code = "INTERNAL_ERROR"
)

type codeInfo struct {
	status  int
	message string
}

var codes = map[Code]codeInfo{
	TargetInvalid:         {http.StatusBadRequest, "Target URL is invalid"},
	RequestInvalid:        {http.StatusBadRequest, "Request is invalid"},
	AuthFailed:            {http.StatusUnauthorized, "Relay authentication failed"},
	TargetForbidden:       {http.StatusForbidden, "Destination is not allowed"},
	NotFound:              {http.StatusNotFound, "Not found"},
	MethodNotAllowed:      {http.StatusMethodNotAllowed, "Method is not allowed"},
	RequestTooLarge:       {http.StatusRequestEntityTooLarge, "Request body is too large"},
	RateLimited:           {http.StatusTooManyRequests, "Rate limit exceeded"},
	ConcurrencyLimited:    {http.StatusTooManyRequests, "Too many concurrent requests"},
	Internal:              {http.StatusInternalServerError, "Internal relay error"},
	UpstreamConnectFailed: {http.StatusBadGateway, "Cannot connect to upstream"},
	UpstreamProtocolError: {http.StatusBadGateway, "Invalid upstream response"},
	UpstreamTimeout:       {http.StatusGatewayTimeout, "Upstream timed out"},
}

// Status returns the HTTP status for the code (500 for unknown codes).
func (c Code) Status() int {
	if ci, ok := codes[c]; ok {
		return ci.status
	}
	return http.StatusInternalServerError
}

// Error is a relay-generated error with a fixed, detail-free message.
type Error struct {
	Code    Code
	Message string
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Message }

// New returns an Error carrying the code's default message.
func New(c Code) *Error {
	msg := codes[c].message
	if msg == "" {
		msg = codes[Internal].message
	}
	return &Error{Code: c, Message: msg}
}

// Write emits e as the relay JSON error body.
func Write(w http.ResponseWriter, requestID string, e *Error) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set(HeaderError, "true")
	h.Set(HeaderRequestID, requestID)
	w.WriteHeader(e.Code.Status())
	body := map[string]map[string]string{"error": {
		"code": string(e.Code), "message": e.Message, "request_id": requestID,
	}}
	_ = json.NewEncoder(w).Encode(body)
}

// NewRequestID returns "req_" followed by 32 random lowercase hex digits.
func NewRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "req_" + hex.EncodeToString(b[:])
}
