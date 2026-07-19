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
// the response. A body carrying an "error" field is treated as a failure even on
// HTTP 200 (some providers, notably GitHub, report failures that way). HTTP
// 400/401 bodies are read so the error code can be parsed and classified rather
// than discarded as a transport error (RFC 6749 §5.2).
//
// This is the shared token-endpoint POST used by both the OAuth2 driver and the
// token_exchange driver, so grant assembly stays per-driver while the transport,
// retry, and error-classification behaviour is defined once.
func postOAuthTokenForm(ctx context.Context, httpClient *http.Client, tokenURL string, form url.Values) (*oauth2TokenResponse, error) {
	retryConfig := httputil.HTTPRetryConfig{
		MaxAttempts:       oauth2MaxRetryAttempts,
		MaxBodySize:       httputil.DefaultMaxBodySize,
		RetryableStatuses: []int{http.StatusTooManyRequests, 500},
		BaseBackoff:       1 * time.Second,
		JitterPercent:     20,
	}
	httpReq := httputil.HTTPRequest{
		Method: http.MethodPost,
		URL:    tokenURL,
		Body:   []byte(form.Encode()),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Accept":       "application/json",
		},
		// RFC 6749 §5.2 returns the error body on HTTP 400 (and 401 for
		// invalid_client). Treat those as readable so the error code can be
		// parsed and classified, rather than discarded as a transport error.
		OKStatuses: []int{http.StatusOK, http.StatusBadRequest, http.StatusUnauthorized},
	}

	body, status, err := httputil.ExecuteWithRetry(ctx, httpClient, httpReq, retryConfig)
	if err != nil {
		// Transport failure, or a status outside OKStatuses (e.g. 5xx after
		// retries). Carry the status so callers can classify it.
		return nil, &tokenEndpointError{status: status, err: err}
	}

	var tokenResp oauth2TokenResponse
	if jsonErr := json.Unmarshal(body, &tokenResp); jsonErr != nil {
		if status != http.StatusOK {
			// A non-2xx with an unparseable body (e.g. a proxy error page):
			// classify by status alone.
			return nil, &tokenEndpointError{status: status, err: fmt.Errorf("status %d: %s", status, string(body))}
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
