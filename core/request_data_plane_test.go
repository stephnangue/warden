package core

import (
	"context"
	"testing"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A provider's data plane is its streaming gateway and the ordinary paths it
// authenticates implicitly, whether or not it has an auto_auth_path; every
// control path, help request and non-provider mount is off it.
func TestDataPlane(t *testing.T) {
	for _, autoAuth := range []string{"", "auth/jwt/"} {
		t.Run("auto_auth_path="+autoAuth, func(t *testing.T) {
			env := newAccessEnv(t, autoAuth)
			c := env.c
			mountGateway(t, c, "aws/", &mockTransparentModeProvider{transparentMode: autoAuth != "", autoAuthPath: autoAuth})
			mountLoginStub(t, c, "jwt")
			ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

			for _, tc := range []struct {
				path string
				op   logical.Operation
				want bool
			}{
				{"aws/gateway/x", logical.ReadOperation, true},
				{"aws/role/r/gateway/x", logical.ReadOperation, true},
				{"aws/gateway/x", logical.HelpOperation, false},
				{"aws/config", logical.ReadOperation, false},
				{"db/access/ro", logical.ReadOperation, true},
				{"db/access/ro", logical.HelpOperation, false},
				{"db/grants/ro", logical.ReadOperation, false},
				{"sys/providers/aws", logical.ReadOperation, false},
				{"sys/mcp", logical.UpdateOperation, false},
				{"auth/jwt/login", logical.UpdateOperation, false},
			} {
				req := &logical.Request{Path: tc.path, Operation: tc.op}
				entry := c.router.MatchingMountEntry(ctx, tc.path)
				isStreaming := c.isStreamingRequest(ctx, tc.path) && tc.op != logical.HelpOperation
				if entry != nil {
					req.MountPoint = entry.Path
				}
				surface, got := c.dataPlane(ctx, req, entry, isStreaming)
				assert.Equal(t, tc.want, got, "%s %s", tc.op, tc.path)
				if !isStreaming {
					assert.Equal(t, got, surface != nil, "%s %s: the surface backend comes with a data-plane answer", tc.op, tc.path)
				}
			}
		})
	}
}

// The full pipeline sets req.DataPlane before policy: an access path is on the
// data plane with no auto_auth_path, the grant path beside it is not.
func TestDataPlane_SetOnRequest(t *testing.T) {
	env := newAccessEnv(t, "")

	_, req, _ := env.get(t, "db/access/ro", nil)
	assert.True(t, req.DataPlane)
	assert.False(t, req.Transparent, "no auto_auth_path: the data plane is not implicit auth")

	_, req, _ = env.get(t, "db/grants/ro", nil)
	assert.False(t, req.DataPlane)

	_, req, _ = env.get(t, "sys/providers", nil)
	assert.False(t, req.DataPlane)
}

// Resolving the data plane is no extra work on a system path: no router
// lookup beyond the mount match, no allocation.
func TestDataPlane_SystemPathDoesNotAllocate(t *testing.T) {
	env := newAccessEnv(t, "")
	c := env.c
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	req := &logical.Request{Path: "sys/providers/aws", Operation: logical.ReadOperation}
	entry := c.router.MatchingMountEntry(ctx, req.Path)
	require.NotNil(t, entry)

	assert.Zero(t, testing.AllocsPerRun(1000, func() {
		_, _ = c.dataPlane(ctx, req, entry, false)
	}))
}
