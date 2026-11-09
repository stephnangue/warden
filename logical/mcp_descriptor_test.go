package logical

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The audit layer deep-copies the descriptor so an async writer cannot
// observe a concurrent handler's mutations. A slice field copied by
// assignment would share its backing array and defeat that — the reason the
// clone discipline is spelled out on these types.
func TestMCPCall_Clone_BreaksSliceAliasing(t *testing.T) {
	orig := MCPCall{
		Method:    "subscriptions/listen",
		URIs:      []string{"repo://a", "repo://b"},
		MatchArgs: map[string]ParamValue{"env": {Kind: ParamString, Str: "prod"}},
	}

	clone := orig.Clone()
	require.Equal(t, orig.URIs, clone.URIs)

	clone.URIs[0] = "repo://mutated"
	assert.Equal(t, "repo://a", orig.URIs[0], "clone shares the URIs backing array")

	clone.MatchArgs["env"] = ParamValue{Kind: ParamString, Str: "dev"}
	assert.Equal(t, "prod", orig.MatchArgs["env"].Str, "clone shares the MatchArgs map")
}

func TestMCPCall_Clone_NilSliceStaysNil(t *testing.T) {
	clone := MCPCall{Method: "tools/list"}.Clone()

	assert.Nil(t, clone.URIs, "a listen that names no resource must not gain an empty slice")
	assert.Nil(t, clone.MatchArgs)
}

func TestMCPRequestDescriptor_Clone_BreaksSliceAliasing(t *testing.T) {
	orig := &MCPRequestDescriptor{
		Calls: []MCPCall{{Method: "subscriptions/listen", URIs: []string{"repo://a"}}},
	}

	clone := orig.Clone()
	clone.Calls[0].URIs[0] = "repo://mutated"

	assert.Equal(t, "repo://a", orig.Calls[0].URIs[0],
		"the descriptor clone must reach the URIs inside each call")
}

func TestMCPRequestDescriptor_Clone_NilAndParseErr(t *testing.T) {
	var nilDesc *MCPRequestDescriptor
	assert.Nil(t, nilDesc.Clone())

	orig := &MCPRequestDescriptor{ParseErr: &MCPParseError{Kind: MCPParseKindMalformedParams, Msg: "bad"}}
	clone := orig.Clone()
	clone.ParseErr.Msg = "mutated"
	assert.Equal(t, "bad", orig.ParseErr.Msg)
}

// RawID is bytes the client controls, and the audit layer's clone must not
// share them with the live request.
func TestMCPCall_Clone_BreaksRawIDAliasing(t *testing.T) {
	orig := MCPCall{Method: "tools/call", RawID: json.RawMessage(`"req-1"`), IDPresent: true}

	clone := orig.Clone()
	require.Equal(t, orig.RawID, clone.RawID)
	assert.True(t, clone.IDPresent)

	clone.RawID[1] = 'X'
	assert.Equal(t, `"req-1"`, string(orig.RawID), "clone shares the RawID backing array")
}

func TestMCPCall_Clone_NilRawIDStaysNil(t *testing.T) {
	clone := MCPCall{Method: "notifications/initialized"}.Clone()

	assert.Nil(t, clone.RawID, "a notification must not gain an empty id")
	assert.False(t, clone.IDPresent)
}

// The audit layer treats the descriptor as a deep-copy field, so every field
// added to it has to be carried. A value field silently dropped by Clone is
// invisible until something reads the clone and finds a zero.
func TestMCPRequestDescriptor_CloneCarriesEveryField(t *testing.T) {
	orig := &MCPRequestDescriptor{
		Calls:             []MCPCall{{Method: "tools/list"}},
		IsBatch:           true,
		ClientInfoName:    "claude-code",
		ClientInfoVersion: "2.1.0",
	}

	clone := orig.Clone()

	assert.True(t, clone.IsBatch, "the outer shape is not recoverable from Calls")
	assert.Equal(t, "claude-code", clone.ClientInfoName)
	assert.Equal(t, "2.1.0", clone.ClientInfoVersion)
}
