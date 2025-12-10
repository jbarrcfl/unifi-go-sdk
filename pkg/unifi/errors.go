package unifi

import (
	"errors"
	"fmt"
)

var (
	ErrBadRequest   = errors.New("bad request")
	ErrUnauthorized = errors.New("unauthorized")
	ErrRateLimited  = errors.New("rate limited")
	ErrServerError  = errors.New("server error")
	ErrBadGateway   = errors.New("bad gateway")
)

type APIError struct {
	StatusCode int
	Message    string
	Err        error
}

func (e *APIError) Error() string {
	return fmt.Sprintf("unifi api error (status %d): %s", e.StatusCode, e.Message)
}

func (e *APIError) Unwrap() error {
	return e.Err
}
