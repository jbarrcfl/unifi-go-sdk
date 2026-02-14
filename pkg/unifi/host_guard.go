package unifi

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// hostGuardTransport wraps an http.RoundTripper and blocks any request whose
// destination host does not match the configured allowed host. This prevents
// credential exfiltration: even if application code is modified to call an
// external URL, the API key can never leave the expected network boundary.
type hostGuardTransport struct {
	inner       http.RoundTripper
	allowedHost string // host[:port] from the configured BaseURL
}

// newHostGuardTransport wraps the given transport so that only requests to
// allowedBaseURL are permitted. All other requests are rejected with an error
// before any bytes hit the network.
func newHostGuardTransport(inner http.RoundTripper, allowedBaseURL string) (*hostGuardTransport, error) {
	parsed, err := url.Parse(allowedBaseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing allowed base URL: %w", err)
	}
	host := parsed.Host
	if host == "" {
		return nil, fmt.Errorf("allowed base URL %q has no host", allowedBaseURL)
	}
	return &hostGuardTransport{
		inner:       inner,
		allowedHost: strings.ToLower(host),
	}, nil
}

func (t *hostGuardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqHost := strings.ToLower(req.URL.Host)
	if reqHost != t.allowedHost {
		return nil, fmt.Errorf(
			"host guard: request to %q blocked — only %q is allowed (possible credential exfiltration attempt)",
			req.URL.Host, t.allowedHost,
		)
	}
	return t.inner.RoundTrip(req)
}
