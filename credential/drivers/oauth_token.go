package drivers

import (
	"context"
	"encoding/json"
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
		Method:  http.MethodPost,
		URL:     tokenURL,
		Body:    body,
		Headers: headers,
		// RFC 6749 §5.2 returns the error body on HTTP 400 (and 401 for
		// invalid_client). Treat those as readable so the error code can be
		// parsed and classified, rather than discarded as a transport error.
		OKStatuses: []int{http.StatusOK, http.StatusBadRequest, http.StatusUnauthorized},
	}

	respBody, status, err := httputil.ExecuteWithRetry(ctx, httpClient, httpReq, retryConfig)
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
