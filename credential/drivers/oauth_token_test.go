package drivers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oauthTokenCapture is a token endpoint that records the one request it receives
// and answers with a fixed status and body.
func oauthTokenCapture(t *testing.T, status int, body string) (*httptest.Server, *http.Request, *[]byte) {
	t.Helper()
	var got http.Request
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = *r.Clone(context.Background())
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server, &got, &gotBody
}

func TestPostOAuthTokenJSON_EncodesGrantAsJSON(t *testing.T) {
	server, req, body := oauthTokenCapture(t, http.StatusOK, `{"access_token":"tok","expires_in":60}`)

	resp, err := postOAuthTokenJSON(context.Background(), server.Client(), server.URL,
		map[string]string{"grant_type": "g", "assertion": "a"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "tok", resp.AccessToken)
	assert.Equal(t, 60, resp.ExpiresIn)

	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	assert.Equal(t, "application/json", req.Header.Get("Accept"))
	var grant map[string]string
	require.NoError(t, json.Unmarshal(*body, &grant))
	assert.Equal(t, map[string]string{"grant_type": "g", "assertion": "a"}, grant)
}

func TestPostOAuthTokenForm_StillFormEncodes(t *testing.T) {
	// The form and JSON posters share one path; the form callers must see exactly
	// the request they always sent.
	server, req, body := oauthTokenCapture(t, http.StatusOK, `{"access_token":"tok"}`)

	_, err := postOAuthTokenForm(context.Background(), server.Client(), server.URL,
		url.Values{"grant_type": {"client_credentials"}}, nil)
	require.NoError(t, err)

	assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
	form, err := url.ParseQuery(string(*body))
	require.NoError(t, err)
	assert.Equal(t, "client_credentials", form.Get("grant_type"))
}

func TestPostOAuthToken_ExtraHeadersCannotOverrideNegotiation(t *testing.T) {
	server, req, _ := oauthTokenCapture(t, http.StatusOK, `{"access_token":"tok"}`)

	_, err := postOAuthTokenJSON(context.Background(), server.Client(), server.URL, map[string]string{}, map[string]string{
		"Content-Type":  "text/plain",
		"Accept":        "text/html",
		"Authorization": "Basic x",
	})
	require.NoError(t, err)
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	assert.Equal(t, "application/json", req.Header.Get("Accept"))
	assert.Equal(t, "Basic x", req.Header.Get("Authorization"))
}

func TestPostOAuthToken_ClassifiesErrorBody(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		wantCode string
		// upstream is the status a failed mint reads through the error:
		// the transport status, or 400 for an OAuth error carried on a 200.
		upstream int
	}{
		{name: "RFC 6749 400", status: http.StatusBadRequest, body: `{"error":"invalid_grant","error_description":"expired"}`, wantCode: "invalid_grant", upstream: http.StatusBadRequest},
		{name: "RFC 6749 401", status: http.StatusUnauthorized, body: `{"error":"invalid_client"}`, wantCode: "invalid_client", upstream: http.StatusUnauthorized},
		{name: "error carried on a 200", status: http.StatusOK, body: `{"error":"access_denied"}`, wantCode: "access_denied", upstream: http.StatusBadRequest},
		{name: "unparseable 400 is classified by status", status: http.StatusBadRequest, body: `<html>bad gateway</html>`, upstream: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, _, _ := oauthTokenCapture(t, tt.status, tt.body)

			_, err := postOAuthTokenJSON(context.Background(), server.Client(), server.URL, map[string]string{}, nil)
			require.Error(t, err)
			var tee *tokenEndpointError
			require.True(t, errors.As(err, &tee), "want a classified tokenEndpointError, got %T", err)
			assert.Equal(t, tt.status, tee.status)
			assert.Equal(t, tt.wantCode, tee.code)

			// A refusal's status is readable through the error, so a failed
			// mint can be answered as a refusal rather than a server error.
			status, ok := credential.UpstreamStatus(fmt.Errorf("mint: %w", err))
			assert.True(t, ok)
			assert.Equal(t, tt.upstream, status)
		})
	}
}

func TestFederatedTokenLifetime(t *testing.T) {
	const fallback, max = time.Minute, time.Hour
	tests := []struct {
		name      string
		expiresIn int
		want      time.Duration
	}{
		{name: "absent takes the fallback", expiresIn: 0, want: fallback},
		{name: "negative takes the fallback", expiresIn: -5, want: fallback},
		{name: "in range is taken as-is", expiresIn: 900, want: 900 * time.Second},
		{name: "exactly the cap", expiresIn: 3600, want: max},
		{name: "past the cap is capped", expiresIn: 3601, want: max},
		// Multiplied first, this would overflow time.Duration and could wrap to a
		// small positive value that passes as a real lifetime.
		{name: "overflowing value is capped", expiresIn: math.MaxInt, want: max},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, federatedTokenLifetime(tt.expiresIn, fallback, max))
		})
	}
}

func TestFederatedLeaseTTL(t *testing.T) {
	const buffer = time.Minute
	tests := []struct {
		name     string
		lifetime time.Duration
		maxTTL   time.Duration
		want     time.Duration
	}{
		{name: "lifetime less the buffer", lifetime: time.Hour, want: 59 * time.Minute},
		{name: "short token keeps half its life", lifetime: time.Minute, want: 30 * time.Second},
		{name: "capped by MaxTTL", lifetime: time.Hour, maxTTL: 10 * time.Minute, want: 10 * time.Minute},
		{name: "MaxTTL above the lease changes nothing", lifetime: time.Hour, maxTTL: 2 * time.Hour, want: 59 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, federatedLeaseTTL(tt.lifetime, buffer, tt.maxTTL))
		})
	}
}

func TestLeaseFromExpiresIn(t *testing.T) {
	opts := LeaseOpts{Fallback: 5 * time.Minute, Max: 24 * time.Hour, Buffer: time.Minute}
	for _, tt := range []struct {
		name      string
		expiresIn int
		maxTTL    time.Duration
		want      time.Duration
	}{
		{name: "absent takes the fallback, less the buffer", expiresIn: 0, want: 4 * time.Minute},
		{name: "in range, less the buffer", expiresIn: 3600, want: 59 * time.Minute},
		{name: "short token keeps half its life", expiresIn: 60, want: 30 * time.Second},
		{name: "overflowing value is capped, not wrapped", expiresIn: math.MaxInt, want: 24*time.Hour - time.Minute},
		{name: "max_ttl caps the lease", expiresIn: 3600, maxTTL: 10 * time.Minute, want: 10 * time.Minute},
	} {
		t.Run(tt.name, func(t *testing.T) {
			o := opts
			o.MaxTTL = tt.maxTTL
			assert.Equal(t, tt.want, LeaseFromExpiresIn(tt.expiresIn, o))
		})
	}
}

func TestExpiryFromExpiresIn(t *testing.T) {
	before := time.Now()
	got := ExpiryFromExpiresIn(math.MaxInt, 0, time.Hour)
	assert.WithinDuration(t, before.Add(time.Hour), got, 5*time.Second, "an outsized expires_in is capped, not wrapped")
	assert.WithinDuration(t, before.Add(10*time.Minute), ExpiryFromExpiresIn(0, 10*time.Minute, time.Hour), 5*time.Second)
	assert.Equal(t, math.MaxInt32, clampExpiresIn(math.MaxInt64))
}

// A source's default_token_ttl stands in for a missing expires_in, and must be
// positive: zero would treat such a token as never expiring.
func TestExchangedTokenLease_DefaultTokenTTL(t *testing.T) {
	source := credential.NewConfig(map[string]string{defaultTokenTTLKey: "10m"})
	assert.Equal(t, 9*time.Minute, exchangedTokenLease(0, source, nil))
	assert.Equal(t, exchangedTokenTTL-exchangedTokenBuffer, exchangedTokenLease(0, credential.NewConfig(nil), nil))

	spec := &credential.CredSpec{MaxTTL: 2 * time.Minute}
	assert.Equal(t, 2*time.Minute, exchangedTokenLease(3600, credential.NewConfig(nil), spec))

	for _, bad := range []string{"0s", "-1m"} {
		err := credential.ValidateSchema(credential.NewConfig(map[string]string{defaultTokenTTLKey: bad}), defaultTokenTTLField())
		assert.Error(t, err, "default_token_ttl=%s", bad)
	}
	assert.NoError(t, credential.ValidateSchema(credential.NewConfig(map[string]string{defaultTokenTTLKey: "90s"}), defaultTokenTTLField()))
}
