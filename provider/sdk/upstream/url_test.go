package upstream

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURL(t *testing.T) {
	cases := []struct {
		name, base, path, query string
		wantPath, wantWire      string
	}{
		{"plain", "https://api.example.com", "/repos/org/x", "", "/repos/org/x", "/repos/org/x"},
		{"empty path keeps the base as is", "https://mcp.example.com/mcp", "", "", "/mcp", "/mcp"},
		{"trailing slash kept", "https://mcp.example.com/mcp", "/", "", "/mcp/", "/mcp/"},
		{"no slash added between", "https://api.example.com/", "/x", "", "//x", "//x"},
		// A decoded path is escaped once and never decoded again.
		{"literal percent-dot", "https://api.example.com", "/a/%2e%2e/b", "", "/a/%2e%2e/b", "/a/%252e%252e/b"},
		{"literal percent", "https://api.example.com", "/100%", "", "/100%", "/100%25"},
		{"space", "https://api.example.com", "/a b", "", "/a b", "/a%20b"},
		// The operator's own escaping in the base survives.
		{"escaped base", "https://gitlab.example.com/api/v4/projects/group%2Fproj", "/issues", "", "/api/v4/projects/group/proj/issues", "/api/v4/projects/group%2Fproj/issues"},
		{"query", "https://api.example.com", "/x", "a=1&b=%2F", "/x", "/x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := URL(tc.base, tc.path, tc.query)
			require.NoError(t, err)
			assert.Equal(t, tc.wantPath, u.Path)
			assert.Equal(t, tc.wantWire, u.EscapedPath())
			assert.Equal(t, tc.query, u.RawQuery)
		})
	}
}

func TestURL_RefusesUnusableBase(t *testing.T) {
	for _, base := range []string{"", "api.example.com", "https://", "://x", "https://x/%zz"} {
		_, err := URL(base, "/x", "")
		assert.Error(t, err, "%q", base)
	}
}

// TestURL_UpstreamReceivesWhatWasAuthorized sends through a real client: the
// upstream decodes the wire path once and gets back the path the request was
// authorized on, never a dot segment.
func TestURL_UpstreamReceivesWhatWasAuthorized(t *testing.T) {
	var gotRequestURI, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestURI, gotPath = r.RequestURI, r.URL.Path
	}))
	defer srv.Close()

	authorized := "/repos/org/public/%2e%2e/secret" // what a %252e%252e request decodes to
	u, err := URL(srv.URL, authorized, "")
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, "/repos/org/public/%252e%252e/secret", gotRequestURI)
	assert.Equal(t, authorized, gotPath)
}
