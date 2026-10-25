package framework

import (
	"context"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The audited upstream URL keeps where the call went and drops what could
// authorize it: every query value and the user-info.
func TestAuditURL(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://api.example.com/v1/chat", "https://api.example.com/v1/chat"},
		{"https://api.example.com/v1/models?api_key=SECRET", "https://api.example.com/v1/models?api_key=%5Bredacted%5D"},
		{
			"https://bucket.s3.amazonaws.com/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA%2F20261025&X-Amz-Security-Token=TOKEN&X-Amz-Signature=SIG",
			"https://bucket.s3.amazonaws.com/key?X-Amz-Algorithm=%5Bredacted%5D&X-Amz-Credential=%5Bredacted%5D&X-Amz-Security-Token=%5Bredacted%5D&X-Amz-Signature=%5Bredacted%5D",
		},
		{"https://user:PASSWORD@git.example.com/repo.git", "https://git.example.com/repo.git"},
		{"https://TOKEN@git.example.com/repo.git?ref=main", "https://git.example.com/repo.git?ref=%5Bredacted%5D"},
		{"https://api.example.com/v1?SECRET-ONLY", "https://api.example.com/v1?%5Bredacted%5D"},
		{"https://api.example.com/v1?a=1&&b=&c", "https://api.example.com/v1?a=%5Bredacted%5D&&b=%5Bredacted%5D&%5Bredacted%5D"},
		{"https://api.example.com/v1?token=a%26b%3Dc", "https://api.example.com/v1?token=%5Bredacted%5D"},
		{"https://api.example.com/v1?dGVzdA==&k=v", "https://api.example.com/v1?%5Bredacted%5D&k=%5Bredacted%5D"},
	} {
		u, err := url.Parse(tc.in)
		require.NoError(t, err)
		assert.Equal(t, tc.want, auditURL(u), tc.in)
	}
}

// A URL with no query and no user-info costs what it did before redaction.
func TestAuditURL_NoQueryAllocatesAsBefore(t *testing.T) {
	u, err := url.Parse("https://api.example.com/v1/chat/completions")
	require.NoError(t, err)
	before := testing.AllocsPerRun(100, func() { _ = u.String() })
	after := testing.AllocsPerRun(100, func() { _ = auditURL(u) })
	assert.Equal(t, before, after)
}

// The streaming handler records the upstream URL a provider proxied to,
// redacted, when the provider set none itself.
func TestStreamingBackend_CapturesRedactedUpstreamURL(t *testing.T) {
	sb := testStreamingBackend()
	sb.StreamingPaths[1].Handler = func(_ context.Context, req *logical.Request, _ *FieldData) error {
		target, err := url.Parse("https://upstream.example.com/v1/messages?key=SECRET")
		if err != nil {
			return err
		}
		req.HTTPRequest.URL = target
		return nil
	}
	req := &logical.Request{
		Operation:      logical.ReadOperation,
		Path:           "gateway/v1/messages",
		Streamed:       true,
		HTTPRequest:    httptest.NewRequest("POST", "/gateway/v1/messages?key=SECRET", nil),
		ResponseWriter: httptest.NewRecorder(),
	}
	_, err := sb.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "https://upstream.example.com/v1/messages?key=%5Bredacted%5D", req.UpstreamURL)
}
