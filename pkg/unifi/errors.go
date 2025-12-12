package unifi

import (
	"errors"
	"fmt"
)

// Sentinel errors for common HTTP status codes.
// Use errors.Is() to check for these errors.
var (
	ErrBadRequest   = errors.New("bad request")   // 400
	ErrUnauthorized = errors.New("unauthorized")  // 401
	ErrForbidden    = errors.New("forbidden")     // 403
	ErrNotFound     = errors.New("not found")     // 404
	ErrConflict     = errors.New("conflict")      // 409
	ErrRateLimited  = errors.New("rate limited")  // 429
	ErrServerError  = errors.New("server error")  // 500
	ErrBadGateway   = errors.New("bad gateway")   // 502
)

func sentinelForStatusCode(statusCode int) error {
	switch statusCode {
	case 400:
		return ErrBadRequest
	case 401:
		return ErrUnauthorized
	case 403:
		return ErrForbidden
	case 404:
		return ErrNotFound
	case 409:
		return ErrConflict
	case 429:
		return ErrRateLimited
	case 500:
		return ErrServerError
	case 502:
		return ErrBadGateway
	default:
		return nil
	}
}

// APIError represents an error returned by the UniFi API.
// It wraps a sentinel error that can be checked with errors.Is().
type APIError struct {
	StatusCode       int
	Message          string
	RetryAfterHeader string
	Err              error
}

func (e *APIError) Error() string {
	return fmt.Sprintf("unifi api error (status %d): %s", e.StatusCode, e.Message)
}

func (e *APIError) Unwrap() error {
	return e.Err
}
