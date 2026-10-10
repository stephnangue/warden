package drivers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/stephnangue/warden/helper/httputil"
)

// postOAuthTokenForm POSTs a form-encoded token request to tokenURL and decodes
// the response, through postOAuthToken.
func postOAuthTokenForm(ctx context.Context, httpClient *http.Client, tokenURL string, form url.Values, extraHeaders map[string]string) (*oauth2TokenResponse, error) {
	return postOAuthToken(ctx, httpClient, tokenURL, "application/x-www-form-urlencoded", []byte(form.Encode()), extraHeaders)
}

// postOAuthTokenFormFunc is postOAuthTokenForm for a form that may be sent only once:
// build is called afresh for every attempt, so a retry carries a new client assertion
// rather than replaying one the authorization server may already have recorded — a
// server enforcing single use (OIDC Core §9) refuses a repeated jti as invalid_client.
//
// A build error means nothing was sent, so it is returned as the builder's own error,
// not as a token-endpoint failure: a signing capability found spent keeps its sentinel
// and its wording, exactly as when it failed before the request was assembled.
func postOAuthTokenFormFunc(ctx context.Context, httpClient *http.Client, tokenURL string, build func() (url.Values, error), extraHeaders map[string]string) (*oauth2TokenResponse, error) {
	bodyFunc := func(int) ([]byte, error) {
		form, err := build()
		if err != nil {
			return nil, err
		}
		return []byte(form.Encode()), nil
	}
	return postOAuthTokenRequest(ctx, httpClient, tokenURL, "application/x-www-form-urlencoded", nil, bodyFunc, extraHeaders)
}

// postOAuthTokenJSON is postOAuthTokenForm for a token endpoint that takes its
// grant as a JSON object rather than a form — Anthropic's, for one. Only the body
// encoding differs; the response, retry, and error classification are the same.
func postOAuthTokenJSON(ctx context.Context, httpClient *http.Client, tokenURL string, grant any, extraHeaders map[string]string) (*oauth2TokenResponse, error) {
	body, err := json.Marshal(grant)
	if err != nil {
		return nil, fmt.Errorf("failed to encode token request: %w", err)
	}
	return postOAuthToken(ctx, httpClient, tokenURL, "application/json", body, extraHeaders)
}

// federatedTokenLifetime converts a token response's expires_in into how long the
// token actually lives. Missing or non-positive takes fallback, which should be
// the shortest lifetime the upstream issues so a guess can only re-mint early.
// Anything past max is capped to it before the multiply: taken as-is, a value
// past ~292 years overflows time.Duration and can wrap to a small positive
// lifetime that would pass as a real one.
func federatedTokenLifetime(expiresIn int, fallback, max time.Duration) time.Duration {
	switch {
	case expiresIn <= 0:
		return fallback
	case expiresIn > int(max/time.Second):
		return max
	default:
		return time.Duration(expiresIn) * time.Second
	}
}

// federatedLeaseTTL is how long the credential cache may serve a federated token:
// its lifetime less buffer, so the next request re-mints while the token is still
// good. A short token would be left with little or nothing after the buffer, so
// the lease never drops below half the lifetime. It is capped at the spec's
// MaxTTL; MinTTL is not applied, since the upstream fixes the lifetime and a floor
// could not lengthen it.
func federatedLeaseTTL(lifetime, buffer, maxTTL time.Duration) time.Duration {
	ttl := lifetime - buffer
	if half := lifetime / 2; ttl < half {
		ttl = half
	}
	if maxTTL > 0 && ttl > maxTTL {
		ttl = maxTTL
	}
	return ttl
}

// postOAuthToken POSTs a token request to tokenURL and decodes the response. A
// body carrying an "error" field is treated as a failure even on HTTP 200 (some
// providers, notably GitHub, report failures that way). HTTP 400/401 bodies are
// read so the error code can be parsed and classified rather than discarded as a
// transport error (RFC 6749 §5.2).
//
// This is the shared token-endpoint POST behind every driver that talks to one,
// so grant assembly and body encoding stay per-driver while the transport, retry,
// and error-classification behaviour is defined once.
func postOAuthToken(ctx context.Context, httpClient *http.Client, tokenURL, contentType string, body []byte, extraHeaders map[string]string) (*oauth2TokenResponse, error) {
	return postOAuthTokenRequest(ctx, httpClient, tokenURL, contentType, body, nil, extraHeaders)
}

// postOAuthTokenRequest is postOAuthToken with the body given either once (body) or
// per attempt (bodyFunc); exactly one is set.
func postOAuthTokenRequest(ctx context.Context, httpClient *http.Client, tokenURL, contentType string, body []byte, bodyFunc func(int) ([]byte, error), extraHeaders map[string]string) (*oauth2TokenResponse, error) {
	retryConfig := httputil.HTTPRetryConfig{
		MaxAttempts:       oauth2MaxRetryAttempts,
		MaxBodySize:       httputil.DefaultMaxBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}
	headers := map[string]string{
		"Content-Type": contentType,
		"Accept":       "application/json",
	}
	// Extra headers carry client authentication that lives outside the body (e.g.
	// client_secret_basic's Authorization header). They cannot override the
	// content negotiation above.
	for k, v := range extraHeaders {
		if k == "Content-Type" || k == "Accept" {
			continue
		}
		headers[k] = v
	}
	httpReq := httputil.HTTPRequest{
		Method:   http.MethodPost,
		URL:      tokenURL,
		Body:     body,
		BodyFunc: bodyFunc,
		Headers:  headers,
		// RFC 6749 §5.2 returns the error body on HTTP 400 (and 401 for
		// invalid_client). Treat those as readable so the error code can be
		// parsed and classified, rather than discarded as a transport error.
		OKStatuses: []int{http.StatusOK, http.StatusBadRequest, http.StatusUnauthorized},
	}

	respBody, status, err := httputil.ExecuteWithRetry(ctx, httpClient, httpReq, retryConfig)
	if be := (*httputil.BodyError)(nil); errors.As(err, &be) {
		// The request was never sent; the failure is the builder's, reported as is.
		return nil, be.Err
	}
	if err != nil {
		// Transport failure, or a status outside OKStatuses (e.g. 5xx after
		// retries). Carry the status so callers can classify it.
		return nil, &tokenEndpointError{status: status, err: err}
	}

	var tokenResp oauth2TokenResponse
	if jsonErr := json.Unmarshal(respBody, &tokenResp); jsonErr != nil {
		if status != http.StatusOK {
			// A non-2xx with an unparseable body (e.g. a proxy error page):
			// classify by status alone.
			return nil, &tokenEndpointError{status: status, err: fmt.Errorf("status %d: %s", status, string(respBody))}
		}
		return nil, fmt.Errorf("failed to decode token response: %w", jsonErr)
	}
	if status != http.StatusOK || tokenResp.Error != "" {
		// An OAuth2 error body — carried on HTTP 400/401, or as an HTTP 200 body
		// by providers like GitHub. Surface the parsed code for classification.
		return nil, &tokenEndpointError{status: status, code: tokenResp.Error, description: tokenResp.ErrorDescription}
	}
	return &tokenResp, nil
}
