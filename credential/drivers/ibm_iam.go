package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/stephnangue/warden/helper/httputil"
	"github.com/stephnangue/warden/logger"
)

// ibmFallbackTokenTTL bounds a token whose lifetime the endpoint declined to state.
// The lease decides how long the bearer keeps being served from cache, so a generous
// guess hands out a token that expired long ago, while a short one costs only another
// mint.
const ibmFallbackTokenTTL = 5 * time.Minute

// ibmIAMTokenResponse represents the IBM Cloud IAM token endpoint response.
type ibmIAMTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Expiration  int64  `json:"expiration"` // Unix timestamp
}

// exchangeIBMAPIKeyForIAMToken exchanges an IBM Cloud API key for an IAM bearer token
// by calling POST {iamEndpoint}/identity/token. Used by both IBMDriver.acquireIAMToken
// (for source-managed API keys) and VaultDriver.fetchDynamicIBMCreds (for Vault-minted
// dynamic API keys).
//
// If httpClient is nil, http.DefaultClient is used. Callers that need TLS configuration
// (custom CA, skip verify) should pass a client built via BuildHTTPClient. log may be
// nil; it carries the one case worth reporting, a response that stated no lifetime.
func exchangeIBMAPIKeyForIAMToken(ctx context.Context, httpClient *http.Client, apiKey, iamEndpoint string, log *logger.GatedLogger) (string, time.Time, error) {
	token, expiry, _, err := exchangeIBMAPIKeyForIAMTokenWithStatus(ctx, httpClient, apiKey, iamEndpoint, log)
	return token, expiry, err
}

// exchangeIBMAPIKeyForIAMTokenWithStatus is exchangeIBMAPIKeyForIAMToken plus the
// HTTP status the endpoint answered with, which ExecuteWithRetry reports even on
// error. Only the chained mint path reads it: there the fetched key is the one
// thing that varies per request, so an authentication refusal is worth telling the
// minting layer about. A key held in config has nothing to re-fetch, so every other
// caller uses the wrapper above.
func exchangeIBMAPIKeyForIAMTokenWithStatus(ctx context.Context, httpClient *http.Client, apiKey, iamEndpoint string, log *logger.GatedLogger) (string, time.Time, int, error) {
	if apiKey == "" {
		return "", time.Time{}, 0, fmt.Errorf("api_key is empty")
	}
	if iamEndpoint == "" {
		iamEndpoint = defaultIBMIAMEndpoint
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	form := url.Values{
		"grant_type": {"urn:ibm:params:oauth:grant-type:apikey"},
		"apikey":     {apiKey},
	}

	respBody, status, err := httputil.ExecuteWithRetry(ctx, httpClient, httputil.HTTPRequest{
		Method: "POST",
		URL:    iamEndpoint + "/identity/token",
		Body:   []byte(form.Encode()),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Accept":       "application/json",
		},
	}, defaultIBMRetryConfig())
	if err != nil {
		return "", time.Time{}, status, fmt.Errorf("IBM IAM token request failed: %w", err)
	}

	var tokenResp ibmIAMTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", time.Time{}, status, fmt.Errorf("failed to decode IAM token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", time.Time{}, status, fmt.Errorf("IAM token response missing access_token")
	}

	// Compute expiry from either expiration (Unix timestamp) or expires_in (seconds)
	var expiry time.Time
	switch {
	case tokenResp.Expiration > 0:
		expiry = time.Unix(tokenResp.Expiration, 0)
	case tokenResp.ExpiresIn > 0:
		expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	default:
		// Nothing here knows how long the token is actually good for, and the
		// credential is served from cache for the whole lease. Fall back to a span
		// short enough that a wrong guess is corrected by a re-mint rather than by
		// an agent presenting a dead bearer.
		if log != nil {
			log.Warn("IAM token response carried no usable expiry; bounding the lease at the fallback lifetime",
				logger.String("fallback", ibmFallbackTokenTTL.String()),
			)
		}
		expiry = time.Now().Add(ibmFallbackTokenTTL)
	}

	return tokenResp.AccessToken, expiry, status, nil
}
