//go:build !warden_e2e_graph_hosts

package msgraph

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A binary built without the e2e tag sends delegated tokens to Microsoft Graph
// and nowhere else.
func TestDefaultBuildAllowsGraphOnly(t *testing.T) {
	assert.Empty(t, buildTagHosts)
	for _, local := range []string{"https://127.0.0.1", "https://127.0.0.1:8443", "https://localhost"} {
		assert.Error(t, Spec.ValidateExtraConfig(map[string]any{"graph_url": local}), local)
	}
}
