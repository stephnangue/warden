package aws

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Every Warden header is stripped before re-signing: the credentials would leak
// to AWS, and the routing selectors name a tenant, role or mount it has no use for.
func TestWardenHeadersToStrip_CoversEveryWardenHeader(t *testing.T) {
	for _, h := range []string{
		"X-Warden-Token", "X-Warden-Agent-Token", "X-Warden-User-Token",
		"X-Warden-Subject-Token", "X-Warden-Actor-Token",
		"X-Warden-Role", "X-Warden-Provider", "X-Warden-Namespace",
	} {
		assert.Contains(t, wardenHeadersToStrip, h)
	}
}
