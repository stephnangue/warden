package msgraph

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

const testPrefix = "https://warden.example.com/v1/msgraph/role/m365/gateway"

func graphResponse(method string, status int, contentType, body string) *http.Response {
	req := httptest.NewRequest(method, "https://graph.microsoft.com/v1.0/me/messages", nil)
	h := http.Header{}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	return &http.Response{
		StatusCode: status, Header: h, Request: req,
		Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)),
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(b)
}

func TestRewriteLinks(t *testing.T) {
	body := `{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#users('x')/messages",` +
		`"value":[{"id":"1","members@odata.nextLink":"https://graph.microsoft.com/v1.0/nested?$skiptoken=n"}],` +
		`"@odata.nextLink":"https://graph.microsoft.com/v1.0/me/messages?$top=10&$skiptoken=abc"}`
	resp := graphResponse(http.MethodGet, http.StatusOK, "application/json; odata.metadata=minimal; charset=utf-8", body)

	require.NoError(t, rewriteLinks(resp, httpproxy.RewriteContext{Prefix: testPrefix, MaxBodySize: 1 << 20}))
	out := readBody(t, resp)

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	var next string
	require.NoError(t, json.Unmarshal(got["@odata.nextLink"], &next))
	assert.Equal(t, testPrefix+"/v1.0/me/messages?$top=10&$skiptoken=abc", next, "the path and query are kept exactly")
	assert.Contains(t, out, "&$skiptoken", "& is not HTML-escaped")
	assert.Contains(t, out, `"@odata.context":"https://graph.microsoft.com/v1.0/$metadata`, "only paging links move")
	assert.Contains(t, out, `"members@odata.nextLink":"https://graph.microsoft.com/v1.0/nested`, "nested links are left alone")
	assert.Equal(t, strconv.Itoa(len(out)), resp.Header.Get("Content-Length"))
	assert.Equal(t, int64(len(out)), resp.ContentLength)
}

func TestRewriteLinks_DeltaAndQualified(t *testing.T) {
	body := `{"value":[],"@odata.deltaLink":"https://GRAPH.microsoft.com/v1.0/me/events/delta?$deltatoken=d",` +
		`"members@odata.nextLink":"https://graph.microsoft.com/v1.0/groups/g/members?$skiptoken=m"}`
	resp := graphResponse(http.MethodGet, http.StatusOK, "application/json", body)
	resp.Request.URL.Host = "GRAPH.microsoft.com"
	require.NoError(t, rewriteLinks(resp, httpproxy.RewriteContext{Prefix: testPrefix}))
	out := readBody(t, resp)
	assert.Contains(t, out, testPrefix+"/v1.0/me/events/delta?$deltatoken=d")
	assert.Contains(t, out, testPrefix+"/v1.0/groups/g/members?$skiptoken=m")
}

func TestRewriteLinks_PassesThroughUntouched(t *testing.T) {
	foreign := `{"@odata.nextLink":"https://evil.example/v1.0/me/messages?$skiptoken=x"}`
	plain := `{"@odata.nextLink":"https://graph.microsoft.com/v1.0/me?x=1"}`
	cases := []struct {
		name string
		resp *http.Response
		body string
	}{
		{"another origin", graphResponse(http.MethodGet, 200, "application/json", foreign), foreign},
		{"not JSON", graphResponse(http.MethodGet, 200, "text/plain", plain), plain},
		{"an error", graphResponse(http.MethodGet, 404, "application/json", plain), plain},
		{"broken JSON", graphResponse(http.MethodGet, 200, "application/json", `{"@odata.nextLink":`), `{"@odata.nextLink":`},
		{"no links", graphResponse(http.MethodGet, 200, "application/json", `{"value":[1,2]}`), `{"value":[1,2]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, rewriteLinks(tc.resp, httpproxy.RewriteContext{Prefix: testPrefix}))
			assert.Equal(t, tc.body, readBody(t, tc.resp))
		})
	}

	t.Run("encoded body", func(t *testing.T) {
		resp := graphResponse(http.MethodGet, 200, "application/json", plain)
		resp.Header.Set("Content-Encoding", "gzip")
		require.NoError(t, rewriteLinks(resp, httpproxy.RewriteContext{Prefix: testPrefix}))
		assert.Equal(t, plain, readBody(t, resp))
	})
}

// A body over the cap is forwarded whole: what was buffered, then the rest.
func TestRewriteLinks_OverCapForwardsEverything(t *testing.T) {
	body := `{"@odata.nextLink":"https://graph.microsoft.com/v1.0/me?x=1","value":"` + strings.Repeat("a", 4096) + `"}`
	resp := graphResponse(http.MethodGet, 200, "application/json", body)
	require.NoError(t, rewriteLinks(resp, httpproxy.RewriteContext{Prefix: testPrefix, MaxBodySize: 100}))
	assert.Equal(t, body, readBody(t, resp))
	assert.Equal(t, int64(len(body)), resp.ContentLength, "length headers are left as received")
}

func TestRewriteRequested(t *testing.T) {
	get := httptest.NewRequest(http.MethodGet, "/v1/msgraph/gateway/v1.0/me/messages", nil)
	post := httptest.NewRequest(http.MethodPost, "/v1/msgraph/gateway/v1.0/me/sendMail", nil)
	assert.True(t, rewriteRequested(get, map[string]any{}), "on by default")
	assert.False(t, rewriteRequested(get, map[string]any{stateRewriteLinks: false}))
	assert.False(t, rewriteRequested(post, map[string]any{}), "only GET is paged")
}

func TestConfigBool(t *testing.T) {
	for in, want := range map[any]bool{true: true, false: false, "true": true, "false": false} {
		got, ok := configBool(in)
		assert.True(t, ok)
		assert.Equal(t, want, got)
	}
	_, ok := configBool("maybe")
	assert.False(t, ok)
	_, ok = configBool(nil)
	assert.False(t, ok)
}
