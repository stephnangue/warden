package gcp

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stephnangue/warden/logical"
)

// Every Warden header (logical.WardenRequestHeaders) is stripped before
// proxying: the credentials would leak upstream, and the routing selectors and
// reserved names mean nothing to it.
func TestHeadersStripped_CoverEveryWardenHeader(t *testing.T) {
	for _, h := range logical.WardenRequestHeaders() {
		assert.Contains(t, headersToRemove, h)
	}
}
