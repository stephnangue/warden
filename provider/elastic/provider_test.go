package elastic

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// es-security-runas-user makes Elasticsearch run the request as another user when
// the minted key's role grants run_as. Forwarded, it would let an agent act past
// the key Warden minted for it.
func TestSpec_StripsRunAsHeader(t *testing.T) {
	h := http.Header{}
	h.Set("es-security-runas-user", "elastic")
	h.Set("Content-Type", "application/json")

	Spec.StripInboundHeaders(h)

	assert.Empty(t, h.Values("es-security-runas-user"))
	assert.Equal(t, "application/json", h.Get("Content-Type"))
}
