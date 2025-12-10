package unifi

import (
	"errors"
	"fmt"
)

var (
	ErrBadRequest   = errors.New("bad request")
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrNotFound     = errors.New("not found")
	ErrRateLimited  = errors.New("rate limited")
	ErrServerError  = errors.New("server error")
	ErrBadGateway   = errors.New("bad gateway")
)

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
