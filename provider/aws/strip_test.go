package aws

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stephnangue/warden/logical"
)

// Every Warden header (logical.WardenRequestHeaders) is stripped before
// re-signing: the credentials would leak to AWS, and the routing selectors name
// a tenant, role or mount it has no use for.
func TestWardenHeadersToStrip_CoversEveryWardenHeader(t *testing.T) {
	for _, h := range logical.WardenRequestHeaders() {
		assert.Contains(t, wardenHeadersToStrip, h)
	}
}
