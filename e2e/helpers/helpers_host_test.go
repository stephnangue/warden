//go:build e2e

package helpers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A "Host" entry in a header map must reach the server as the request's Host.
//
// net/http reads the Host from the request field, not the header map, and drops a
// "Host" header set through Header.Set — so before applyHeaders existed a caller
// asking for one got no host and no error, and the request went out named after
// the URL. That is not a hypothetical: a gateway test passed
// "Host: ecs.cn-hangzhou.aliyuncs.com" and reached Warden as 127.0.0.1.
//
// It matters because a provider can resolve its upstream target from the inbound
// Host — provider/alicloud does exactly that — so a test that cannot set one
// cannot drive that provider at all.
func TestApplyHeaders_HostReachesTheServer(t *testing.T) {
	const wantHost = "ecs.cn-hangzhou.aliyuncs.com"

	var gotHost, gotHostHeader, gotOther string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotHostHeader = r.Header.Get("Host")
		gotOther = r.Header.Get("X-Warden-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	status, _ := DoRequest(t, "GET", srv.URL, map[string]string{
		"Host":           wantHost,
		"X-Warden-Token": "not-a-real-token",
	}, "")

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if gotHost != wantHost {
		t.Errorf("r.Host = %q, want %q — a Host entry must set the request field", gotHost, wantHost)
	}
	// Go moves Host out of the header map on the way in, so the server sees it
	// only on the field. Asserted so the mechanism is not mistaken for a bug.
	if gotHostHeader != "" {
		t.Errorf("r.Header[Host] = %q, want empty", gotHostHeader)
	}
	if gotOther != "not-a-real-token" {
		t.Errorf("other headers must be unaffected, got %q", gotOther)
	}
}

// The key is matched however it is cased, since a header map is not canonicalised
// until it is applied.
func TestApplyHeaders_HostIsCaseInsensitive(t *testing.T) {
	for _, key := range []string{"Host", "host", "HOST"} {
		t.Run(key, func(t *testing.T) {
			var gotHost string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotHost = r.Host
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			DoRequest(t, "GET", srv.URL, map[string]string{key: "oss-cn-hangzhou.aliyuncs.com"}, "")

			if gotHost != "oss-cn-hangzhou.aliyuncs.com" {
				t.Errorf("r.Host = %q, want the value passed under %q", gotHost, key)
			}
		})
	}
}

// Without a Host entry the request is named after its URL, as before.
func TestApplyHeaders_NoHostEntryLeavesTheURLHost(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	DoRequest(t, "GET", srv.URL, map[string]string{"X-Warden-Token": "not-a-real-token"}, "")

	// srv.URL is http://127.0.0.1:<port>; the server sees that authority.
	if gotHost == "" {
		t.Error("r.Host is empty, want the URL's authority")
	}
}
