package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The extractor accepts five credential types and reads the token from a
// different field for three of them, so its branches are a matrix rather than a
// list: every type must find its own field, and a type reading the wrong one
// would fail as "missing token" rather than visibly mismatching.

func TestExtractBearerToken_AcceptedTypes(t *testing.T) {
	cases := []struct {
		name     string
		credType string
		field    string
	}{
		{"oauth bearer token", credential.TypeOAuthBearerToken, "api_key"},
		{"api key", credential.TypeAPIKey, "api_key"},
		{"gcp access token", credential.TypeGCPAccessToken, "access_token"},
		{"azure bearer token", credential.TypeAzureBearerToken, "access_token"},
		{"github token", credential.TypeGitHubToken, "token"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers, err := extractBearerToken(&logical.Request{
				Credential: &credential.Credential{
					Type: tc.credType,
					Data: map[string]string{tc.field: "the-token"},
				},
			})
			require.NoError(t, err)
			assert.Equal(t, "Bearer the-token", headers["Authorization"])
			assert.Len(t, headers, 1)
		})
	}
}

// Every accepted type must reject an empty token. The branch is shared, but it
// is reachable from five places and a type wired to the wrong field would land
// here rather than fail visibly — so each is worth its own row.
func TestExtractBearerToken_EmptyTokenPerType(t *testing.T) {
	cases := []struct {
		name     string
		credType string
		data     map[string]string
	}{
		{"oauth bearer token", credential.TypeOAuthBearerToken, map[string]string{"api_key": ""}},
		{"api key", credential.TypeAPIKey, map[string]string{}},
		{"gcp access token", credential.TypeGCPAccessToken, map[string]string{"access_token": ""}},
		{"azure bearer token", credential.TypeAzureBearerToken, map[string]string{}},
		{"github token", credential.TypeGitHubToken, map[string]string{"token": ""}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := extractBearerToken(&logical.Request{
				Credential: &credential.Credential{Type: tc.credType, Data: tc.data},
			})
			assert.ErrorContains(t, err, "missing token")
		})
	}
}

// A credential carrying the right value under the wrong field is indistinguishable
// from an empty one — worth pinning, because it is what a mis-wired type would do.
func TestExtractBearerToken_TokenUnderTheWrongField(t *testing.T) {
	_, err := extractBearerToken(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeGitHubToken,
			Data: map[string]string{"api_key": "the-token"},
		},
	})
	assert.ErrorContains(t, err, "missing token")
}

func TestExtractBearerToken_NoCredential(t *testing.T) {
	_, err := extractBearerToken(&logical.Request{})
	assert.ErrorContains(t, err, "no credential available")
}

func TestExtractBearerToken_UnsupportedType(t *testing.T) {
	_, err := extractBearerToken(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeVaultToken,
			Data: map[string]string{"token": "the-token"},
		},
	})
	assert.ErrorContains(t, err, "unsupported credential type for mcp")
}

// The enforcement gate decides whether a request is subject to body-authoritative
// mcp { } rules. It has to decline anything whose body is not a JSON-RPC call —
// SSE reconnects and session closes carry no method to authorise — while
// admitting every shape a real client's POST takes.

func TestShouldEnforceMCPPolicy(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		contentType string
		want        bool
	}{
		{"json-rpc post", http.MethodPost, "application/json", true},
		{"json-rpc post with charset", http.MethodPost, "application/json; charset=utf-8", true},
		{"sse reconnect", http.MethodGet, "application/json", false},
		{"session close", http.MethodDelete, "application/json", false},
		{"post with no content type", http.MethodPost, "", false},
		{"post with a non-json body", http.MethodPost, "text/plain", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/v1/mcp/gateway/", strings.NewReader("{}"))
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			got := shouldEnforceMCPPolicy(&logical.Request{HTTPRequest: r})
			assert.Equal(t, tc.want, got)
		})
	}
}

// Declining must be safe to call on a request that carries no HTTP layer at all,
// since the gate runs before anything has validated the request's shape.
func TestShouldEnforceMCPPolicy_NilSafe(t *testing.T) {
	got := shouldEnforceMCPPolicy(nil)
	assert.False(t, got)

	got = shouldEnforceMCPPolicy(&logical.Request{})
	assert.False(t, got)
}

func TestSpec(t *testing.T) {
	assert.Equal(t, "mcp", Spec.Name)
	assert.Equal(t, "mcp_url", Spec.URLConfigKey)
	assert.NotNil(t, Spec.ExtractCredentials)
	assert.NotNil(t, Spec.ShouldEnforceMCPPolicy)
	assert.NotNil(t, Factory)
	// Streaming bodies must not be parsed: MCP responses may be SSE, and buffering
	// one would stall a session rather than proxy it.
	assert.False(t, Spec.ParseStreamBody)
	// No default Accept: MCP clients negotiate their own, and forcing one would
	// break a one-shot JSON client.
	assert.Empty(t, Spec.DefaultAccept)
}
