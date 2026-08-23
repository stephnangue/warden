package dualgateway

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The dual-mode gateway carries a user principal in API mode and cannot in S3
// mode, so these rows pin the boundary between them rather than a single
// per-mount answer.
//
// This replaces TestExtractTokens_AgentOnly, which pinned agent-only everywhere.
// That test existed to make exactly this change deliberate rather than silent,
// which is what it did.

// API mode uses the same channel rules as every other provider: the dedicated
// agent header leaves Authorization free for the user.
func TestExtractTokens_APIMode_CarriesAUser(t *testing.T) {
	for _, tc := range []struct {
		name      string
		headers   map[string]string
		cert      bool
		userLeg   bool
		wantAgent string
		wantUser  string
	}{
		{
			name:      "agent-token header frees Authorization for the user",
			headers:   map[string]string{"X-Warden-Agent-Token": "ag", "Authorization": "Bearer u"},
			userLeg:   true,
			wantAgent: "ag",
			wantUser:  "u",
		},
		{
			name:      "client cert authenticates the agent, bearer is the user",
			headers:   map[string]string{"Authorization": "Bearer u"},
			cert:      true,
			userLeg:   true,
			wantAgent: "",
			wantUser:  "u",
		},
		{
			name:      "off the user leg the same request yields no user",
			headers:   map[string]string{"X-Warden-Agent-Token": "ag", "Authorization": "Bearer u"},
			userLeg:   false,
			wantAgent: "u",
			wantUser:  "",
		},
		{
			name:      "a lone bearer is the agent, not a user",
			headers:   map[string]string{"Authorization": "Bearer b"},
			userLeg:   true,
			wantAgent: "b",
			wantUser:  "",
		},
		{
			name:      "the operator credential never carries a user",
			headers:   map[string]string{"X-Warden-Token": "w", "Authorization": "Bearer u"},
			userLeg:   true,
			wantAgent: "w",
			wantUser:  "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/v1/scaleway/gateway/instance/v1/servers", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if tc.cert {
				r = withClientCert(r)
			}
			agent, user := extractTokens(r, tc.userLeg)
			assert.Equal(t, tc.wantAgent, agent, "agent")
			assert.Equal(t, tc.wantUser, user, "user")
		})
	}
}

// S3 mode stays agent-only, and not by choice: the SigV4 signature occupies
// Authorization and the access key it names is the agent identity, so there is
// nowhere for a second principal to ride. provider/aws is agent-only for the
// same reason.
func TestExtractTokens_S3Mode_IsAgentOnly(t *testing.T) {
	const sigv4Header = "AWS4-HMAC-SHA256 Credential=eyJhbGciOiJSUzI1NiJ9/20260410/fr-par/s3/aws4_request, SignedHeaders=host, Signature=abc"

	t.Run("the access key is the agent, and there is no user", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/scaleway/gateway/bucket/key", nil)
		r.Header.Set("Authorization", sigv4Header)

		agent, user := extractTokens(r, true)
		assert.Equal(t, "eyJhbGciOiJSUzI1NiJ9", agent)
		assert.Empty(t, user, "a SigV4 request has no channel for a user")
	})

	// The non-transparent S3 path: the caller authenticates to Warden with the
	// operator credential and Warden mints the keys the request is re-signed
	// with. The signature is still verified against the access key, so the two
	// coexist and X-Warden-Token has to win.
	//
	// userLeg is off deliberately. On a protected-resource mount core refuses
	// X-Warden-Token beside a non-empty Authorization before extraction runs,
	// and a signed request always has one — so asserting this with the leg on
	// would pin behaviour no request can reach.
	t.Run("the operator credential outranks the signature", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/scaleway/gateway/bucket/key", nil)
		r.Header.Set("Authorization", sigv4Header)
		r.Header.Set("X-Warden-Token", "w")

		agent, user := extractTokens(r, false)
		assert.Equal(t, "w", agent)
		assert.Empty(t, user)
	})

	// The dedicated agent channel does not displace the signature: the upstream
	// will be told about the signed identity, so that is the one authenticated
	// here. The header is ignored, and stripped before forwarding.
	t.Run("the agent-token channel does not displace the signature", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/scaleway/gateway/bucket/key", nil)
		r.Header.Set("Authorization", sigv4Header)
		r.Header.Set("X-Warden-Agent-Token", "ag")

		agent, user := extractTokens(r, true)
		assert.Equal(t, "eyJhbGciOiJSUzI1NiJ9", agent)
		assert.Empty(t, user)
	})

	// A certificate cannot stand in for the signature: S3 clients sign, and the
	// signed identity is the one the upstream will be told about.
	t.Run("a client certificate does not add a user", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/scaleway/gateway/bucket/key", nil)
		r.Header.Set("Authorization", sigv4Header)
		r = withClientCert(r)

		_, user := extractTokens(r, true)
		assert.Empty(t, user)
	})
}
