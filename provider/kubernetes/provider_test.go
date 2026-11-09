package kubernetes

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// An agent that could forward Impersonate-* would act past the service account
// Warden minted for it whenever that account holds the impersonate verb. Every
// member of the family is stripped, the extra attributes by prefix since the client
// picks their names; the rest of the request is left alone.
func TestSpec_StripsImpersonationHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Impersonate-User", "system:admin")
	h.Add("Impersonate-Group", "system:masters")
	h.Add("Impersonate-Group", "system:authenticated")
	h.Set("Impersonate-Uid", "06f6ce97-e2c5-4ab8-7ba5-7654dd08d52b")
	h.Set("Impersonate-Extra-Scopes", "view")
	h.Set("Impersonate-Extra-Acme.com%2fproject", "some-project")
	h.Set("Content-Type", "application/json")

	Spec.StripInboundHeaders(h)

	for name := range h {
		assert.False(t, strings.HasPrefix(strings.ToLower(name), "impersonate-"), "%s reached the API server", name)
	}
	assert.Equal(t, "application/json", h.Get("Content-Type"))
}
