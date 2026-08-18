package core

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsTransparentRequest_AgentTokenHeader guards the distinction between the
// two agent channels.
//
// X-Warden-Token is an already-issued session token, so it short-circuits
// transparent auth and goes to explicit token validation. X-Warden-Agent-Token
// carries a JWT or JWT-SVID that still needs a transparent LOGIN — the token
// store only ever looks tokens up, never logs one in, so short-circuiting it
// would make every fresh credential on that header fail closed. That would
// break the flagship flow this whole feature exists for: a bearer-JWT agent
// presenting itself out of band so Authorization is free for the user.
func TestIsTransparentRequest_AgentTokenHeader(t *testing.T) {
	core := createTestCore(t)

	backend := &mockTransparentModeProvider{
		transparentMode: true,
		autoAuthPath:    "auth/agent-jwt/",
		defaultAuthRole: "agent",
	}

	newReq := func(headers map[string]string) *logical.Request {
		hr := httptest.NewRequest(http.MethodPost, "/v1/mcp/gateway/messages", nil)
		for k, v := range headers {
			hr.Header.Set(k, v)
		}
		return &logical.Request{Path: "mcp/gateway/messages", HTTPRequest: hr}
	}

	t.Run("X-Warden-Agent-Token still routes through transparent auth", func(t *testing.T) {
		req := newReq(map[string]string{
			"X-Warden-Agent-Token": "eyJ.agent.jwt",
			"Authorization":        "Bearer user-token",
		})
		transparent, _ := core.isTransparentRequest(req, backend)
		require.True(t, transparent,
			"a JWT on the agent channel needs a transparent login; skipping it would "+
				"send an unissued credential to the lookup-only token store and fail closed")
	})

	t.Run("X-Warden-Token short-circuits to explicit auth", func(t *testing.T) {
		req := newReq(map[string]string{"X-Warden-Token": "already-issued-session-token"})
		transparent, _ := core.isTransparentRequest(req, backend)
		assert.False(t, transparent, "an issued session token wants explicit validation")
	})

	t.Run("both headers: the session token still wins", func(t *testing.T) {
		req := newReq(map[string]string{
			"X-Warden-Token":       "already-issued-session-token",
			"X-Warden-Agent-Token": "eyJ.agent.jwt",
		})
		transparent, _ := core.isTransparentRequest(req, backend)
		assert.False(t, transparent)
	})
}
