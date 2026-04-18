package drivers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExchangeIBMAPIKeyForIAMToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/identity/token", r.URL.Path)
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		require.NoError(t, r.ParseForm())
		require.Equal(t, "urn:ibm:params:oauth:grant-type:apikey", r.FormValue("grant_type"))
		require.Equal(t, "my-api-key", r.FormValue("apikey"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token-abc",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"expiration":   time.Now().Add(1 * time.Hour).Unix(),
		})
	}))
	defer srv.Close()

	token, expiry, err := exchangeIBMAPIKeyForIAMToken(context.Background(), srv.Client(), "my-api-key", srv.URL)
	require.NoError(t, err)
	assert.Equal(t, "token-abc", token)
	assert.True(t, expiry.After(time.Now()))
}

func TestExchangeIBMAPIKeyForIAMToken_EmptyAPIKey(t *testing.T) {
	_, _, err := exchangeIBMAPIKeyForIAMToken(context.Background(), nil, "", "https://iam.cloud.ibm.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key is empty")
}

func TestExchangeIBMAPIKeyForIAMToken_EmptyEndpointUsesDefault(t *testing.T) {
	// With an empty endpoint, the helper should fall back to the default IBM IAM URL.
	// We can't hit the real IAM endpoint in tests, but we can verify the default
	// constant is used by checking the error mentions a network failure against it.
	// Use a very short timeout to avoid a slow test.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, _, err := exchangeIBMAPIKeyForIAMToken(ctx, &http.Client{Timeout: 10 * time.Millisecond}, "some-key", "")
	require.Error(t, err)
	// Either context deadline or DNS/connect error is acceptable — we just want to confirm
	// it attempted to call the default endpoint rather than failing early.
	assert.Contains(t, err.Error(), "IBM IAM token request failed")
}

func TestExchangeIBMAPIKeyForIAMToken_MissingAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token_type": "Bearer",
			"expires_in": 3600,
		})
	}))
	defer srv.Close()

	_, _, err := exchangeIBMAPIKeyForIAMToken(context.Background(), srv.Client(), "key", srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing access_token")
}

func TestExchangeIBMAPIKeyForIAMToken_ExpiresInFallback(t *testing.T) {
	// Response with expires_in but no expiration field — expiry should be computed from expires_in.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token-xyz",
			"token_type":   "Bearer",
			"expires_in":   60,
		})
	}))
	defer srv.Close()

	_, expiry, err := exchangeIBMAPIKeyForIAMToken(context.Background(), srv.Client(), "key", srv.URL)
	require.NoError(t, err)
	remaining := time.Until(expiry)
	assert.True(t, remaining > 30*time.Second && remaining <= 61*time.Second,
		"expiry should be ~60s from now, got %s", remaining)
}

func TestExchangeIBMAPIKeyForIAMToken_NoExpiryInfoFallbackTo1h(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token-xyz",
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	_, expiry, err := exchangeIBMAPIKeyForIAMToken(context.Background(), srv.Client(), "key", srv.URL)
	require.NoError(t, err)
	remaining := time.Until(expiry)
	assert.True(t, remaining > 50*time.Minute && remaining <= 61*time.Minute,
		"expiry should fall back to ~1h, got %s", remaining)
}

func TestExchangeIBMAPIKeyForIAMToken_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	_, _, err := exchangeIBMAPIKeyForIAMToken(context.Background(), srv.Client(), "key", srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode IAM token response")
}
