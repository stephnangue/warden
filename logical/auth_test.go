package logical

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPDecision_JSONRoundTrip(t *testing.T) {
	t.Run("full populated decision", func(t *testing.T) {
		original := &MCPDecision{
			Method:      "tools/call",
			Name:        "delete_repository",
			Decision:    "deny",
			MatchedRule: "delete_*",
			RuleType:    "denied_tools",
			ParamName:   "path",
			ParamValue:  ".env.production",
		}

		encoded, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded MCPDecision
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		assert.Equal(t, *original, decoded)
	})

	t.Run("minimal decision (allow with empty optional fields)", func(t *testing.T) {
		original := &MCPDecision{
			Method:      "tools/list",
			Decision:    "allow",
			MatchedRule: "tools/list",
			RuleType:    "allowed_methods",
		}

		encoded, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded MCPDecision
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		assert.Equal(t, *original, decoded)
	})
}

func TestMCPDecision_OmitEmpty(t *testing.T) {
	// Optional fields (name, param_name, param_value) must be omitted
	// from the serialised form when empty so non-name-bearing and
	// non-param decisions produce compact audit records.
	d := &MCPDecision{
		Method:      "tools/list",
		Decision:    "allow",
		MatchedRule: "tools/list",
		RuleType:    "allowed_methods",
	}

	encoded, err := json.Marshal(d)
	require.NoError(t, err)

	s := string(encoded)
	assert.NotContains(t, s, "name")
	assert.NotContains(t, s, "param_name")
	assert.NotContains(t, s, "param_value")
	assert.Contains(t, s, `"method":"tools/list"`)
	assert.Contains(t, s, `"decision":"allow"`)
	assert.Contains(t, s, `"rule_type":"allowed_methods"`)
}

func TestMCPDecision_Clone_Nil(t *testing.T) {
	var d *MCPDecision
	assert.Nil(t, d.Clone())
}

func TestMCPDecision_Clone_DeepCopy(t *testing.T) {
	original := &MCPDecision{
		Method:      "tools/call",
		Name:        "delete_repository",
		Decision:    "deny",
		MatchedRule: "delete_*",
		RuleType:    "denied_tools",
		ParamName:   "path",
		ParamValue:  ".env.production",
	}

	clone := original.Clone()
	require.NotNil(t, clone)
	assert.Equal(t, *original, *clone)

	// Mutating the clone must not affect the original.
	clone.Name = "mutated"
	clone.MatchedRule = "mutated"
	assert.Equal(t, "delete_repository", original.Name)
	assert.Equal(t, "delete_*", original.MatchedRule)
}

func TestConditionResult_Clone(t *testing.T) {
	assert.Nil(t, (*ConditionResult)(nil).Clone())

	original := &ConditionResult{
		Decision:   "deny",
		Expression: "call.args.amount <= 1500",
		Inputs:     map[string]string{"call.args.amount": "2000"},
	}
	clone := original.Clone()
	require.NotNil(t, clone)
	assert.Equal(t, *original, *clone)

	// Mutating the clone's map must not affect the original.
	clone.Inputs["call.args.amount"] = "0"
	clone.Decision = "allow"
	assert.Equal(t, "2000", original.Inputs["call.args.amount"])
	assert.Equal(t, "deny", original.Decision)
}

func TestConditionResult_Sanitize(t *testing.T) {
	(*ConditionResult)(nil).Sanitize() // nil-safe

	c := &ConditionResult{
		Decision:   "deny",
		Expression: "call.args.x <= 1\x00",
		ErrorKind:  "type_mismatch\n",
		Inputs:     map[string]string{"call.args.x\x07": "ab\x1bcd"},
	}
	c.Sanitize()
	assert.Equal(t, "call.args.x <= 1", c.Expression)
	assert.Equal(t, "type_mismatch", c.ErrorKind)
	assert.Equal(t, map[string]string{"call.args.x": "abcd"}, c.Inputs)
}
