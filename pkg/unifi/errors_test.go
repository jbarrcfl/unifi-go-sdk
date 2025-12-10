package unifi

import (
	"errors"
	"testing"
)

func TestAPIErrorError(t *testing.T) {
	err := &APIError{
		StatusCode: 404,
		Message:    "host not found",
		Err:        ErrNotFound,
	}

	expected := "unifi api error (status 404): host not found"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestAPIErrorUnwrap(t *testing.T) {
	err := &APIError{
		StatusCode: 404,
		Message:    "host not found",
		Err:        ErrNotFound,
	}

	if !errors.Is(err, ErrNotFound) {
		t.Error("expected errors.Is(err, ErrNotFound) to be true")
	}
}

func TestAPIErrorUnwrapNil(t *testing.T) {
	err := &APIError{
		StatusCode: 418,
		Message:    "teapot",
		Err:        nil,
	}

	if errors.Is(err, ErrNotFound) {
		t.Error("expected errors.Is(err, ErrNotFound) to be false")
	}
	if errors.Is(err, ErrBadRequest) {
		t.Error("expected errors.Is(err, ErrBadRequest) to be false")
	}
}

func TestSentinelErrors(t *testing.T) {
	sentinels := []error{
		ErrBadRequest,
		ErrUnauthorized,
		ErrForbidden,
		ErrNotFound,
		ErrRateLimited,
		ErrServerError,
		ErrBadGateway,
	}

	for _, sentinel := range sentinels {
		if sentinel == nil {
			t.Error("sentinel error should not be nil")
		}
		if sentinel.Error() == "" {
			t.Error("sentinel error message should not be empty")
		}
	}
}

func TestErrorsAs(t *testing.T) {
	err := &APIError{
		StatusCode: 401,
		Message:    "invalid api key",
		Err:        ErrUnauthorized,
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Error("expected errors.As to succeed")
	}
	if apiErr.StatusCode != 401 {
		t.Errorf("expected status code 401, got %d", apiErr.StatusCode)
	}
}
