package unifi

import (
	"net/http"
	"testing"
)

func TestHostGuardTransport_AllowsMatchingHost(t *testing.T) {
	guard, err := newHostGuardTransport(http.DefaultTransport, "https://192.168.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req, _ := http.NewRequest("GET", "https://192.168.1.1/api/self", nil)
	// We can't actually execute the request (no server), but we can verify
	// the guard doesn't block it by checking it reaches the inner transport.
	// Use a mock transport instead.
	called := false
	guard.inner = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: 200}, nil
	})

	_, err = guard.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected request to be allowed, got: %v", err)
	}
	if !called {
		t.Fatal("inner transport was not called")
	}
}

func TestHostGuardTransport_BlocksMismatchedHost(t *testing.T) {
	guard, err := newHostGuardTransport(http.DefaultTransport, "https://192.168.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req, _ := http.NewRequest("GET", "https://evil.example.com/steal?key=secret", nil)
	_, err = guard.RoundTrip(req)
	if err == nil {
		t.Fatal("expected request to be blocked")
	}
	if got := err.Error(); got == "" {
		t.Fatal("error message should not be empty")
	}
}

func TestHostGuardTransport_BlocksDifferentPort(t *testing.T) {
	guard, err := newHostGuardTransport(http.DefaultTransport, "https://192.168.1.1:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req, _ := http.NewRequest("GET", "https://192.168.1.1:8443/api/self", nil)
	_, err = guard.RoundTrip(req)
	if err == nil {
		t.Fatal("expected request to different port to be blocked")
	}
}

func TestHostGuardTransport_CaseInsensitive(t *testing.T) {
	guard, err := newHostGuardTransport(http.DefaultTransport, "https://MyController.local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	guard.inner = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: 200}, nil
	})

	req, _ := http.NewRequest("GET", "https://mycontroller.local/api/self", nil)
	_, err = guard.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected case-insensitive match, got: %v", err)
	}
	if !called {
		t.Fatal("inner transport was not called")
	}
}

func TestNewHostGuardTransport_RejectsEmptyHost(t *testing.T) {
	_, err := newHostGuardTransport(http.DefaultTransport, "not-a-url")
	if err == nil {
		t.Fatal("expected error for URL with no host")
	}
}

// roundTripFunc adapts a function to http.RoundTripper for testing.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
