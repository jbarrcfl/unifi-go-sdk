package unifi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestIsRetryableNilError(t *testing.T) {
	if isRetryable(nil) {
		t.Error("isRetryable(nil) should return false")
	}
}

func TestIsRetryableWrappedError(t *testing.T) {
	apiErr := &APIError{StatusCode: 429}
	wrapped := fmt.Errorf("wrapped: %w", apiErr)

	if !isRetryable(wrapped) {
		t.Error("isRetryable should return true for wrapped 429 error")
	}
}

func TestIsNetworkError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil", nil, false},
		{"DeadlineExceeded", context.DeadlineExceeded, true},
		{"wrapped DeadlineExceeded", fmt.Errorf("wrapped: %w", context.DeadlineExceeded), true},
		{"Canceled", context.Canceled, false},
		{"regular error", errors.New("some error"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNetworkError(tt.err); got != tt.expected {
				t.Errorf("isNetworkError() = %v, want %v", got, tt.expected)
			}
		})
	}
}

type mockTimeoutError struct {
	timeout bool
}

func (e mockTimeoutError) Error() string   { return "mock timeout error" }
func (e mockTimeoutError) Timeout() bool   { return e.timeout }
func (e mockTimeoutError) Temporary() bool { return false }

func TestIsNetworkErrorTimeout(t *testing.T) {
	timeoutErr := mockTimeoutError{timeout: true}
	nonTimeoutErr := mockTimeoutError{timeout: false}

	// Wrap in net.OpError to satisfy net.Error interface check
	netTimeout := &net.OpError{Err: timeoutErr}
	netNonTimeout := &net.OpError{Err: nonTimeoutErr}

	if !isNetworkError(netTimeout) {
		t.Error("isNetworkError should return true for timeout network error")
	}

	if isNetworkError(netNonTimeout) {
		t.Error("isNetworkError should return false for non-timeout network error")
	}
}

func TestApplyBackoffWithJitterBounds(t *testing.T) {
	maxWait := 60 * time.Second

	for i := 0; i < 100; i++ {
		wait := applyBackoffWithJitter(0, 0, maxWait)
		// First attempt: base (1s) + jitter (0-0.5s) = 1s to 1.5s
		if wait < 1*time.Second || wait > 1500*time.Millisecond {
			t.Errorf("attempt 0: wait %v outside expected bounds [1s, 1.5s]", wait)
		}
	}

	for i := 0; i < 100; i++ {
		wait := applyBackoffWithJitter(0, 1, maxWait)
		// Second attempt: base*2 (2s) + jitter (0-1s) = 2s to 3s
		if wait < 2*time.Second || wait > 3*time.Second {
			t.Errorf("attempt 1: wait %v outside expected bounds [2s, 3s]", wait)
		}
	}
}

func TestApplyBackoffWithJitterMaxBackoff(t *testing.T) {
	maxWait := 120 * time.Second

	for i := 0; i < 100; i++ {
		// High attempt number should hit maxBackoff (60s) before jitter
		wait := applyBackoffWithJitter(0, 10, maxWait)
		// Should be capped at maxBackoff (60s) + jitter (0-30s) = 60s to 90s
		if wait < 60*time.Second || wait > 90*time.Second {
			t.Errorf("high attempt: wait %v outside expected bounds [60s, 90s]", wait)
		}
	}
}

func TestApplyBackoffWithJitterServerWaitRespected(t *testing.T) {
	maxWait := 120 * time.Second

	// When server provides wait time, it should be used instead of calculated backoff
	wait := applyBackoffWithJitter(30*time.Second, 0, maxWait)
	if wait != 30*time.Second {
		t.Errorf("server wait should be respected: got %v, want 30s", wait)
	}
}

func TestApplyBackoffWithJitterMaxWaitRespected(t *testing.T) {
	maxWait := 10 * time.Second

	// Even with high backoff, should not exceed maxWait
	wait := applyBackoffWithJitter(0, 10, maxWait)
	if wait > maxWait {
		t.Errorf("wait %v exceeds maxWait %v", wait, maxWait)
	}

	// Server wait should also be capped
	wait = applyBackoffWithJitter(60*time.Second, 0, maxWait)
	if wait > maxWait {
		t.Errorf("server wait %v exceeds maxWait %v", wait, maxWait)
	}
}

func TestExecuteWithRetrySuccess(t *testing.T) {
	attempts := 0
	err := executeWithRetry(context.Background(), nil, 3, 60*time.Second, func() error {
		attempts++
		return nil
	})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", attempts)
	}
}

func TestExecuteWithRetryEventualSuccess(t *testing.T) {
	attempts := 0
	err := executeWithRetry(context.Background(), nil, 3, 1*time.Second, func() error {
		attempts++
		if attempts < 3 {
			return &APIError{StatusCode: 503}
		}
		return nil
	})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestExecuteWithRetryNonRetryable(t *testing.T) {
	attempts := 0
	err := executeWithRetry(context.Background(), nil, 3, 60*time.Second, func() error {
		attempts++
		return &APIError{StatusCode: 404}
	})
	if err == nil {
		t.Error("expected error, got nil")
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt for non-retryable error, got %d", attempts)
	}
}

func TestExecuteWithRetryContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	err := executeWithRetry(ctx, nil, 10, 60*time.Second, func() error {
		attempts++
		return &APIError{StatusCode: 503}
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}
