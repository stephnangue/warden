package drivers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

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
	}{
		{name: "RFC 6749 400", status: http.StatusBadRequest, body: `{"error":"invalid_grant","error_description":"expired"}`, wantCode: "invalid_grant"},
		{name: "RFC 6749 401", status: http.StatusUnauthorized, body: `{"error":"invalid_client"}`, wantCode: "invalid_client"},
		{name: "error carried on a 200", status: http.StatusOK, body: `{"error":"access_denied"}`, wantCode: "access_denied"},
		{name: "unparseable 400 is classified by status", status: http.StatusBadRequest, body: `<html>bad gateway</html>`},
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
		})
	}
}
