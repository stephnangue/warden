package alicloud

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestExtractTokens_AgentOnly pins the scoping decision: Alibaba Cloud never yields a
// user principal, even on a protected-resource mount and even when the request
// carries every channel that would free Authorization elsewhere.
//
// This is a product decision, not a structural limit — the security-token slot is free in cert-transparent mode, but ACS3/OSS SDK
// clients have no interactive protected-resource bootstrap — so the
// assertion exists to make a future change to it deliberate rather than silent.
func TestExtractTokens_AgentOnly(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers map[string]string
		cert    bool
	}{
		{"bearer on Authorization", map[string]string{"Authorization": "Bearer b"}, false},
		{"agent-token header and bearer", map[string]string{"X-Warden-Agent-Token": "ag", "Authorization": "Bearer u"}, false},
		{"cert and bearer", map[string]string{"Authorization": "Bearer u"}, true},
		{"warden token and bearer", map[string]string{"X-Warden-Token": "w", "Authorization": "Bearer u"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/v1/alicloud/gateway/", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if tc.cert {
				r = withClientCert(r)
			}
			_, user := extractTokens(r, true)
			assert.Empty(t, user, "alicloud is agent-only; userLeg must not produce a user")
		})
	}
}
