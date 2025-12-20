package unifi

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

// Shared constants for HTTP clients and retry logic.
const (
	// Response body size limits to prevent memory exhaustion from malformed responses.
	maxErrorBodySize    = 64 * 1024        // 64KB limit for error response bodies
	maxResponseBodySize = 10 * 1024 * 1024 // 10MB limit for success response bodies

	// Default HTTP client timeout, used by both SiteManagerClient and NetworkClient.
	defaultTimeout = 30 * time.Second

	// Exponential backoff parameters for retry logic.
	baseBackoff    = 1 * time.Second  // Initial backoff duration
	maxBackoff     = 60 * time.Second // Maximum backoff before jitter
	jitterFraction = 0.5              // Up to 50% additional random delay
)

var retryAfterRegex = regexp.MustCompile(`retry after ([\d.]+)s`)

func isRetryable(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case 429, 500, 502, 503, 504:
			return true
		}
		return false
	}
	return isNetworkError(err)
}

func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

func applyBackoffWithJitter(serverWait time.Duration, attempt int, maxWait time.Duration) time.Duration {
	var wait time.Duration
	if serverWait > 0 {
		wait = serverWait
	} else {
		backoff := baseBackoff << attempt
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
		jitter := time.Duration(float64(backoff) * jitterFraction * rand.Float64())
		wait = backoff + jitter
	}
	if wait > maxWait {
		wait = maxWait
	}
	return wait
}

func parseRetryAfterHeader(header string) time.Duration {
	if header == "" {
		return 0
	}
	if secs, err := strconv.Atoi(header); err == nil {
		return time.Duration(secs) * time.Second
	}
	if secs, err := strconv.ParseFloat(header, 64); err == nil {
		return time.Duration(secs * float64(time.Second))
	}
	if t, err := http.ParseTime(header); err == nil {
		d := time.Until(t)
		if d > 0 {
			return d
		}
		return 0
	}
	return 0
}

func parseRetryAfterBody(msg string) time.Duration {
	matches := retryAfterRegex.FindStringSubmatch(msg)
	if len(matches) == 2 {
		if secs, err := strconv.ParseFloat(matches[1], 64); err == nil {
			return time.Duration(secs * float64(time.Second))
		}
	}
	return 0
}

func executeWithRetry(ctx context.Context, logger Logger, maxRetries int, maxRetryWait time.Duration, fn func() error) error {
	var lastErr error
	maxAttempts := maxRetries + 1

	for attempt := range maxAttempts {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		if !isRetryable(lastErr) {
			return lastErr
		}

		if attempt >= maxAttempts-1 {
			break
		}

		wait := time.Duration(0)
		var apiErr *APIError
		if errors.As(lastErr, &apiErr) && apiErr.StatusCode == 429 {
			wait = parseRetryAfterHeader(apiErr.RetryAfterHeader)
			if wait == 0 {
				wait = parseRetryAfterBody(apiErr.Message)
			}
		}
		wait = applyBackoffWithJitter(wait, attempt, maxRetryWait)

		if logger != nil {
			logger.Printf("retrying in %v (attempt %d/%d)", wait, attempt+1, maxRetries)
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}

	return lastErr
}
