package core

import (
	"context"
	"net/http"
	"testing"

	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const casTestPolicy = `
path "secret/*" {
  capabilities = ["read"]
}
`

// writePolicy drives the update handler the way a client does, returning the
// response so a caller can assert on the refusal as well as the success.
func writePolicy(t *testing.T, backend *SystemBackend, ctx context.Context, name string, extra map[string]interface{}) *logical.Response {
	t.Helper()
	raw := map[string]interface{}{"name": name, "policy": casTestPolicy}
	for k, v := range extra {
		raw[k] = v
	}
	schema := backend.pathPolicies()[0].Fields
	resp, err := backend.handlePolicyUpdate(ctx,
		createTestRequest(logical.UpdateOperation, "policies/cbp/"+name, raw),
		createFieldData(schema, raw))
	require.NoError(t, err)
	return resp
}

// createPolicy drives the create handler specifically. POST maps to
// CreateOperation on the wire, and the path registers a separate callback for
// it, so a test that only ever updates would not notice the create handler
// losing its assignment.
func createPolicy(t *testing.T, backend *SystemBackend, ctx context.Context, name string, extra map[string]interface{}) *logical.Response {
	t.Helper()
	raw := map[string]interface{}{"name": name, "policy": casTestPolicy}
	for k, v := range extra {
		raw[k] = v
	}
	schema := backend.pathPolicies()[0].Fields
	resp, err := backend.handlePolicyCreate(ctx,
		createTestRequest(logical.CreateOperation, "policies/cbp/"+name, raw),
		createFieldData(schema, raw))
	require.NoError(t, err)
	return resp
}

func readPolicyVersion(t *testing.T, backend *SystemBackend, ctx context.Context, name string) (int, bool) {
	t.Helper()
	raw := map[string]interface{}{"name": name}
	schema := backend.pathPolicies()[0].Fields
	resp, err := backend.handlePolicyRead(ctx,
		createTestRequest(logical.ReadOperation, "policies/cbp/"+name, raw),
		createFieldData(schema, raw))
	require.NoError(t, err)
	require.Nil(t, resp.Err, "read: %+v", resp.Data)
	return resp.Data["data_version"].(int), resp.Data["cas_required"].(bool)
}

// TestPolicyCAS_RequiredIsSettable pins the write half of check-and-set. The
// store has always honoured a sticky cas_required, but no field carried it, so
// the flag was never true and every policy write was blind however carefully a
// client tried to behave.
func TestPolicyCAS_RequiredIsSettable(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// Turning the flag on is itself a guarded write: the store ORs the incoming
	// flag with the stored one before deciding whether a cas is needed, so the
	// enabling write must carry one. On a policy that does not exist yet that
	// means -1, the must-not-exist form.
	resp := writePolicy(t, backend, ctx, "guarded", map[string]interface{}{"cas_required": true})
	require.NotNil(t, resp.Err, "enabling the flag without a cas must be refused")
	assert.Contains(t, resp.Err.Error(), "check-and-set parameter required")

	resp = writePolicy(t, backend, ctx, "guarded", map[string]interface{}{"cas": -1, "cas_required": true})
	require.Nil(t, resp.Err, "enabling at creation with cas=-1: %+v", resp.Data)

	version, required := readPolicyVersion(t, backend, ctx, "guarded")
	assert.Equal(t, 1, version)
	assert.True(t, required, "cas_required must be persisted and reported")

	// A blind write is now refused.
	resp = writePolicy(t, backend, ctx, "guarded", nil)
	require.NotNil(t, resp.Err, "a blind write must be refused once cas_required is set")
	assert.Contains(t, resp.Err.Error(), "check-and-set parameter required")

	// The policy is untouched by the refusal.
	version, _ = readPolicyVersion(t, backend, ctx, "guarded")
	assert.Equal(t, 1, version)

	// Supplying the current version succeeds.
	resp = writePolicy(t, backend, ctx, "guarded", map[string]interface{}{"cas": 1, "cas_required": true})
	require.Nil(t, resp.Err, "matching cas: %+v", resp.Data)
	version, _ = readPolicyVersion(t, backend, ctx, "guarded")
	assert.Equal(t, 2, version)
}

// TestPolicyCAS_RequiredIsSettableAtCreate covers the other write handler. POST
// maps to CreateOperation and the path registers a separate callback, so the
// assignment exists twice and only one of them is on the path a client takes to
// create a policy.
func TestPolicyCAS_RequiredIsSettableAtCreate(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	resp := createPolicy(t, backend, ctx, "made", map[string]interface{}{"cas": -1, "cas_required": true})
	require.Nil(t, resp.Err, "create with cas_required: %+v", resp.Data)

	_, required := readPolicyVersion(t, backend, ctx, "made")
	assert.True(t, required, "the create handler must carry cas_required too")

	// And it binds: a blind write is refused.
	require.NotNil(t, writePolicy(t, backend, ctx, "made", nil).Err)
}

// TestPolicyCAS_OmittingRequiredClearsIt pins the consequence of taking the flag
// from every write: a caller who updates policy text with a valid cas but says
// nothing about cas_required disarms the guard. That is upstream's behaviour and
// what makes lifting possible at all, but it is a sharp edge — an operator
// editing a guarded policy has to keep asserting the flag or lose it.
func TestPolicyCAS_OmittingRequiredClearsIt(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	require.Nil(t, writePolicy(t, backend, ctx, "sharp", map[string]interface{}{"cas": -1, "cas_required": true}).Err)

	// A correct, careful write that simply does not mention the flag.
	require.Nil(t, writePolicy(t, backend, ctx, "sharp", map[string]interface{}{"cas": 1}).Err)

	_, required := readPolicyVersion(t, backend, ctx, "sharp")
	assert.False(t, required, "omitting cas_required clears it — pinned, not endorsed")
}

// TestPolicyCAS_RequiredCanBeLifted keeps the flag from being a one-way door.
// It is taken from each write rather than carried over, so clearing it is an
// ordinary write — which still has to satisfy the requirement it is lifting.
func TestPolicyCAS_RequiredCanBeLifted(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	require.Nil(t, writePolicy(t, backend, ctx, "liftable", map[string]interface{}{"cas": -1, "cas_required": true}).Err)

	// Lifting it blindly is refused — the flag still applies to this write.
	resp := writePolicy(t, backend, ctx, "liftable", map[string]interface{}{"cas_required": false})
	require.NotNil(t, resp.Err, "lifting must itself satisfy the requirement")

	// With a matching cas it is lifted.
	resp = writePolicy(t, backend, ctx, "liftable", map[string]interface{}{"cas": 1, "cas_required": false})
	require.Nil(t, resp.Err, "lifting with cas: %+v", resp.Data)

	_, required := readPolicyVersion(t, backend, ctx, "liftable")
	assert.False(t, required)

	// And blind writes work again.
	require.Nil(t, writePolicy(t, backend, ctx, "liftable", nil).Err)
}

// TestPolicyCAS_MismatchIsBadRequest pins the status. A caller who loses a race
// was told the server broke: the check-and-set errors carried no status of
// their own, so the wire mapping fell through to its default.
func TestPolicyCAS_MismatchIsBadRequest(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	require.Nil(t, writePolicy(t, backend, ctx, "raced", nil).Err)

	// All three check-and-set refusals, each previously a 500.
	cases := []struct {
		name  string
		extra map[string]interface{}
	}{
		{"stale cas", map[string]interface{}{"cas": 99}},
		{"create cas on an existing policy", map[string]interface{}{"cas": -1}},
		{"cas omitted where required", map[string]interface{}{"cas_required": true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := writePolicy(t, backend, ctx, "raced", tc.extra)
			require.NotNil(t, resp.Err, "must be refused")
			assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(resp.Err),
				"a lost race is the caller's problem, not a 500")
		})
	}
}
