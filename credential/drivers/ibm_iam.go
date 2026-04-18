package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

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
// (custom CA, skip verify) should pass a client built via BuildHTTPClient.
func exchangeIBMAPIKeyForIAMToken(ctx context.Context, httpClient *http.Client, apiKey, iamEndpoint string) (string, time.Time, error) {
	if apiKey == "" {
		return "", time.Time{}, fmt.Errorf("api_key is empty")
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

	respBody, _, err := ExecuteWithRetry(ctx, httpClient, HTTPRequest{
		Method: "POST",
		URL:    iamEndpoint + "/identity/token",
		Body:   []byte(form.Encode()),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Accept":       "application/json",
		},
	}, defaultIBMRetryConfig())
	if err != nil {
		return "", time.Time{}, fmt.Errorf("IBM IAM token request failed: %w", err)
	}

	var tokenResp ibmIAMTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to decode IAM token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("IAM token response missing access_token")
	}

	// Compute expiry from either expiration (Unix timestamp) or expires_in (seconds)
	var expiry time.Time
	if tokenResp.Expiration > 0 {
		expiry = time.Unix(tokenResp.Expiration, 0)
	} else if tokenResp.ExpiresIn > 0 {
		expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	} else {
		expiry = time.Now().Add(1 * time.Hour) // IBM IAM tokens have ~1h TTL
	}

	return tokenResp.AccessToken, expiry, nil
}
