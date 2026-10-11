package aws

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The transport sets no header timeout of its own: the mount's timeout is the
// deadline of every forwarded request, and a fixed one here would cut a slow
// model call short of it.
func TestTransport_NoResponseHeaderTimeout(t *testing.T) {
	assert.Zero(t, newTransport().ResponseHeaderTimeout)

	tlsTransport, err := newTransportWithTLS("", true)
	require.NoError(t, err)
	assert.Zero(t, tlsTransport.ResponseHeaderTimeout)
}
