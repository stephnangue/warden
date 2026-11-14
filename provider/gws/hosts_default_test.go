//go:build !warden_e2e_gws_hosts

package gws

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A binary built without the e2e tag sends a user's token only to the Google host
// its request path names: there is no upstream to configure.
func TestDefaultBuildRefusesOverride(t *testing.T) {
	assert.Empty(t, buildTagHosts)
	for _, local := range []string{"https://127.0.0.1", "https://127.0.0.1:8443", "https://localhost", "https://gmail.googleapis.com"} {
		assert.Error(t, Spec.ValidateExtraConfig(map[string]any{urlConfigKey: local}), local)
	}
}
