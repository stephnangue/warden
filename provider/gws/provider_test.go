package gws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

const gw = "/v1/gws/role/ws/gateway"

func defaultState() map[string]any { return map[string]any{} }

func TestResolveUpstream(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		target       string
		providerURL  string
		state        map[string]any
		wantURL      string
		wantDrop     int
		wantBypass   bool
		wantNoAccept bool
	}{
		{name: "default host", method: "GET", target: gw + "/gmail.googleapis.com/gmail/v1/users/me/messages",
			wantURL: "https://gmail.googleapis.com", wantDrop: 1},
		{name: "drive and calendar live on www", method: "GET", target: gw + "/www.googleapis.com/drive/v3/files",
			wantURL: "https://www.googleapis.com", wantDrop: 1},
		{name: "a host the mount does not allow is not addressed", method: "GET", target: gw + "/storage.googleapis.com/storage/v1/b"},
		{name: "a host outside google is not addressed", method: "GET", target: gw + "/evil.example.com/x"},
		{name: "a port is not a host", method: "GET", target: gw + "/gmail.googleapis.com:8443/gmail/v1/x"},
		{name: "configured host outside the defaults", method: "GET", target: gw + "/keep.googleapis.com/v1/notes",
			state:   map[string]any{framework.HostAllowlistKey: []string{".keep.googleapis.com"}},
			wantURL: "https://keep.googleapis.com", wantDrop: 1},
		{name: "configured list replaces the defaults", method: "GET", target: gw + "/gmail.googleapis.com/gmail/v1/x",
			state: map[string]any{framework.HostAllowlistKey: []string{".keep.googleapis.com"}}},
		{name: "upload is binary", method: "POST", target: gw + "/www.googleapis.com/upload/drive/v3/files?uploadType=resumable",
			wantURL: "https://www.googleapis.com", wantDrop: 1, wantBypass: true, wantNoAccept: true},
		{name: "resumable path is binary", method: "PUT", target: gw + "/gmail.googleapis.com/resumable/upload/gmail/v1/users/me/messages/send",
			wantURL: "https://gmail.googleapis.com", wantDrop: 1, wantBypass: true, wantNoAccept: true},
		{name: "a download keeps its own Accept", method: "GET", target: gw + "/www.googleapis.com/drive/v3/files/abc?alt=media",
			wantURL: "https://www.googleapis.com", wantDrop: 1, wantNoAccept: true},
		// alt=media is the caller's to add: on a write it must not stop policy
		// reading the JSON body.
		{name: "alt=media on a write is still parsed", method: "PATCH", target: gw + "/www.googleapis.com/drive/v3/files/abc?alt=media",
			wantURL: "https://www.googleapis.com", wantDrop: 1},
		{name: "the e2e stand-in gets the whole path", method: "GET", target: gw + "/gmail.googleapis.com/gmail/v1/x",
			providerURL: "https://127.0.0.1:8443", wantURL: "https://127.0.0.1:8443"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := tc.state
			if state == nil {
				state = defaultState()
			}
			d, ok := resolveUpstream(httptest.NewRequest(tc.method, tc.target, nil), tc.providerURL, state)
			require.True(t, ok)
			assert.Equal(t, tc.wantURL, d.UpstreamURL)
			assert.Equal(t, tc.wantDrop, d.DropSegments)
			assert.Equal(t, tc.wantBypass, d.BypassBodyParsing)
			assert.Equal(t, tc.wantNoAccept, d.SkipDefaultAccept)
		})
	}

	_, ok := resolveUpstream(httptest.NewRequest("GET", "/v1/gws/config", nil), "", defaultState())
	assert.False(t, ok)
}

// The common request allocates nothing to find its upstream.
func TestResolveUpstream_DefaultHostAllocatesNothing(t *testing.T) {
	r := httptest.NewRequest("GET", gw+"/gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=10", nil)
	state := defaultState()
	allocs := testing.AllocsPerRun(100, func() { _, _ = resolveUpstream(r, "", state) })
	assert.Zero(t, allocs)
}

func refuse(t *testing.T, target, providerURL string, state map[string]any) (int, error) {
	t.Helper()
	if state == nil {
		state = defaultState()
	}
	return Spec.RefuseRequest(httptest.NewRequest("GET", target, nil), providerURL, state)
}

func TestRefuseRequest(t *testing.T) {
	const gmail = "https://gmail.googleapis.com"
	tests := []struct {
		name        string
		target      string
		providerURL string
		state       map[string]any
		status      int
		err         error
	}{
		{name: "allowed", target: gw + "/gmail.googleapis.com/gmail/v1/users/me/messages", providerURL: gmail},
		{name: "batchDelete is a method policy sees", target: gw + "/gmail.googleapis.com/gmail/v1/users/me/messages/batchDelete", providerURL: gmail},
		{name: "batchUpdate is a method policy sees", target: gw + "/sheets.googleapis.com/v4/spreadsheets/x:batchUpdate", providerURL: "https://sheets.googleapis.com"},
		{name: "no host", target: gw, status: 400, err: errNoHost},
		{name: "a host alone", target: gw + "/gmail.googleapis.com", status: 400, err: errNoHost},
		{name: "a host and a slash", target: gw + "/gmail.googleapis.com/", status: 400, err: errNoHost},
		{name: "not a hostname", target: gw + "/127.0.0.1/x", status: 400},
		{name: "uppercase", target: gw + "/Gmail.googleapis.com/x", status: 400},
		{name: "not allowed", target: gw + "/storage.googleapis.com/storage/v1/b", status: 403, err: errHostNotAllowed},
		{name: "a suffix is not the host", target: gw + "/gmail.googleapis.com.evil.test/x", status: 403, err: errHostNotAllowed},
		{name: "upstream that is not the path's host", target: gw + "/gmail.googleapis.com/gmail/v1/x",
			providerURL: "https://www.googleapis.com", status: 500, err: errUpstreamNotTrusted},
		{name: "no upstream", target: gw + "/gmail.googleapis.com/gmail/v1/x", status: 500, err: errUpstreamNotTrusted},
		{name: "batch", target: gw + "/www.googleapis.com/batch/drive/v3", providerURL: "https://www.googleapis.com", status: 400, err: errBatchNotSupported},
		{name: "gmail's batch path", target: gw + "/gmail.googleapis.com/batch", providerURL: gmail, status: 400, err: errBatchNotSupported},
		{name: "batch in capitals", target: gw + "/gmail.googleapis.com/BATCH/gmail/v1", providerURL: gmail, status: 400, err: errBatchNotSupported},
		{name: "batch with parameters", target: gw + "/gmail.googleapis.com/batch;x=1/gmail/v1", providerURL: gmail, status: 400, err: errBatchNotSupported},
		{name: "batch behind a backslash", target: gw + `/gmail.googleapis.com/%5Cbatch`, providerURL: gmail, status: 400, err: errBatchNotSupported},
		{name: "an access token in the query", target: gw + "/gmail.googleapis.com/gmail/v1/x?access_token=t", providerURL: gmail, status: 400, err: errCredentialInQuery},
		{name: "an oauth token in the query", target: gw + "/gmail.googleapis.com/gmail/v1/x?a=1&oauth_token=t", providerURL: gmail, status: 400, err: errCredentialInQuery},
		{name: "an API key in the query", target: gw + "/gmail.googleapis.com/gmail/v1/x?KEY=k", providerURL: gmail, status: 400, err: errCredentialInQuery},
		{name: "an encoded key name", target: gw + "/gmail.googleapis.com/gmail/v1/x?acc%65ss_token=t", providerURL: gmail, status: 400, err: errCredentialInQuery},
		{name: "a value naming a key is fine", target: gw + "/gmail.googleapis.com/gmail/v1/x?q=key", providerURL: gmail},
		{name: "$batch", target: gw + "/www.googleapis.com/$batch", providerURL: "https://www.googleapis.com", status: 400, err: errBatchNotSupported},
		{name: "a bearer token in the query", target: gw + "/gmail.googleapis.com/gmail/v1/x?bearer_token=t", providerURL: gmail, status: 400, err: errCredentialInQuery},
		{name: "a billing project", target: gw + "/gmail.googleapis.com/gmail/v1/x?userProject=p", providerURL: gmail, status: 400, err: errCredentialInQuery},
		{name: "a key as a system parameter", target: gw + "/gmail.googleapis.com/gmail/v1/x?$key=k", providerURL: gmail, status: 400, err: errCredentialInQuery},
		{name: "a billing project as a system parameter", target: gw + "/gmail.googleapis.com/gmail/v1/x?$userProject=p", providerURL: gmail, status: 400, err: errCredentialInQuery},
		{name: "headers restated in the query", target: gw + "/gmail.googleapis.com/gmail/v1/x?$httpHeaders=X-HTTP-Method-Override:DELETE", providerURL: gmail, status: 400, err: errCredentialInQuery},
		{name: "the method restated in the query", target: gw + "/gmail.googleapis.com/gmail/v1/x?%24httpMethod=DELETE", providerURL: gmail, status: 400, err: errCredentialInQuery},
		{name: "the body restated in the query", target: gw + "/gmail.googleapis.com/gmail/v1/x?$req=%7B%7D", providerURL: gmail, status: 400, err: errCredentialInQuery},
		{name: "response-shaping system parameters are fine", target: gw + "/gmail.googleapis.com/gmail/v1/x?$fields=id&$alt=json&$prettyPrint=false&$.xgafv=2", providerURL: gmail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, err := refuse(t, tc.target, tc.providerURL, tc.state)
			if tc.status == 0 {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tc.status, status)
			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
			}
		})
	}
}

// The common request allocates nothing to be let through either.
func TestRefuseRequest_AllowedRequestAllocatesNothing(t *testing.T) {
	r := httptest.NewRequest("GET", gw+"/gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=10&$fields=messages", nil)
	state := defaultState()
	allocs := testing.AllocsPerRun(100, func() {
		_, _ = Spec.RefuseRequest(r, "https://gmail.googleapis.com", state)
	})
	assert.Zero(t, allocs)

	w := httptest.NewRequest("POST", gw+"/gmail.googleapis.com/gmail/v1/users/me/labels", strings.NewReader(`{"name":"x"}`))
	w.Header.Set("Content-Type", "application/json; charset=utf-8")
	allocs = testing.AllocsPerRun(100, func() {
		_, _ = Spec.RefuseRequest(w, "https://gmail.googleapis.com", state)
	})
	assert.Zero(t, allocs, "nor does a JSON write")
}

// Only a body policy can read reaches Google: JSON, outside the upload paths,
// on a method whose body core parses.
func TestRefuseRequest_Body(t *testing.T) {
	const (
		gmail  = "https://gmail.googleapis.com"
		www    = "https://www.googleapis.com"
		labels = gw + "/gmail.googleapis.com/gmail/v1/users/me/labels"
	)
	tests := []struct {
		name        string
		method      string
		target      string
		providerURL string
		contentType string
		alsoLabel   string // a second Content-Type header
		body        string
		chunked     bool
		status      int
		err         error
	}{
		{name: "json", method: "POST", target: labels, providerURL: gmail, contentType: "application/json", body: `{}`},
		{name: "json with a charset, in capitals", method: "POST", target: labels, providerURL: gmail, contentType: "Application/JSON; charset=UTF-8", body: `{}`},
		{name: "a +json type", method: "PATCH", target: labels + "/l1", providerURL: gmail, contentType: "application/merge-patch+json", body: `{}`},
		{name: "json on another method core parses", method: "OPTIONS", target: labels, providerURL: gmail, contentType: "application/json", body: `{}`},
		{name: "no body, whatever the label", method: "POST", target: gw + "/gmail.googleapis.com/gmail/v1/users/me/messages/m1/trash", providerURL: gmail, contentType: "text/plain"},
		// Core reads an unlabelled body as JSON; how Google reads one is unknown.
		{name: "no label", method: "POST", target: labels, providerURL: gmail, body: `{}`, status: 415, err: errBodyNotJSON},
		{name: "a blank label", method: "POST", target: labels, providerURL: gmail, contentType: " ", body: `{}`, status: 415, err: errBodyNotJSON},
		// Core reads the first label; Google gets both.
		{name: "a second label", method: "POST", target: labels, providerURL: gmail, contentType: "application/json", alsoLabel: "application/x-www-form-urlencoded", body: `"&name=x&"`, status: 415, err: errBodyNotJSON},
		{name: "a list in one label, ending in +json", method: "POST", target: labels, providerURL: gmail, contentType: "application/x-www-form-urlencoded, application/x+json", body: `"&name=x&"`, status: 415, err: errBodyNotJSON},
		{name: "a list after a json parameter", method: "POST", target: labels, providerURL: gmail, contentType: "application/json; a=b, application/x-www-form-urlencoded", body: `"&name=x&"`, status: 415, err: errBodyNotJSON},
		{name: "json with a quoted parameter", method: "POST", target: labels, providerURL: gmail, contentType: `application/json; charset="UTF-8"`, body: `{}`},
		{name: "a no-break space TrimSpace drops", method: "POST", target: labels, providerURL: gmail, contentType: " application/json", body: `{}`, status: 415, err: errBodyNotJSON},
		{name: "a letter ToLower folds into ASCII", method: "POST", target: labels, providerURL: gmail, contentType: "applİcation/json", body: `{}`, status: 415, err: errBodyNotJSON},
		{name: "text", method: "POST", target: labels, providerURL: gmail, contentType: "text/plain", body: `{}`, status: 415, err: errBodyNotJSON},
		{name: "json+protobuf", method: "POST", target: labels, providerURL: gmail, contentType: "application/json+protobuf", body: `[]`, status: 415, err: errBodyNotJSON},
		{name: "binary protobuf", method: "POST", target: labels, providerURL: gmail, contentType: "application/x-protobuf", body: "\x0a\x01x", status: 415, err: errBodyNotJSON},
		{name: "a form, which core parses but Google may read otherwise", method: "POST", target: labels, providerURL: gmail, contentType: "application/x-www-form-urlencoded", body: "name=x", status: 415, err: errBodyNotJSON},
		{name: "multipart outside an upload path", method: "POST", target: labels, providerURL: gmail, contentType: "multipart/related; boundary=b", body: "--b--", status: 415, err: errBodyNotJSON},
		// U+017F folds to s under EqualFold but not under ToLower, so core reads
		// this as some other type and parses nothing: it must not pass for JSON.
		{name: "a +json lookalike", method: "POST", target: labels, providerURL: gmail, contentType: "application/x+jſon", body: `{}`, status: 415, err: errBodyNotJSON},
		{name: "a chunked body of unknown length", method: "POST", target: labels, providerURL: gmail, contentType: "text/plain", body: `{}`, chunked: true, status: 415, err: errBodyNotJSON},
		{name: "a body on a GET", method: "GET", target: labels, providerURL: gmail, contentType: "application/json", body: `{}`, status: 400, err: errBodyOnRead},
		{name: "a body on a DELETE", method: "DELETE", target: labels + "/l1", providerURL: gmail, contentType: "application/json", body: `{}`, status: 400, err: errBodyOnRead},
		{name: "a body on a HEAD", method: "HEAD", target: labels, providerURL: gmail, contentType: "application/json", body: `{}`, status: 400, err: errBodyOnRead},
		{name: "a chunked body on a GET", method: "GET", target: labels, providerURL: gmail, contentType: "application/json", body: `{}`, chunked: true, status: 400, err: errBodyOnRead},
		{name: "text on another method core parses", method: "OPTIONS", target: labels, providerURL: gmail, contentType: "text/plain", body: `{}`, status: 415, err: errBodyNotJSON},
		// Exempt exactly where core skips parsing: resolveUpstream reads the path
		// the same lenient way.
		{name: "an upload path in capitals", method: "POST", target: gw + "/www.googleapis.com/Upload/drive/v3/files", providerURL: www, contentType: "text/plain", body: "x"},
		{name: "a multipart upload", method: "POST", target: gw + "/www.googleapis.com/upload/drive/v3/files?uploadType=multipart", providerURL: www, contentType: "multipart/related; boundary=b", body: "--b--"},
		{name: "a resumable chunk", method: "PUT", target: gw + "/www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=s1", providerURL: www, contentType: "application/octet-stream", body: "\x00\x01"},
		{name: "a raw message send", method: "POST", target: gw + "/gmail.googleapis.com/upload/gmail/v1/users/me/messages/send?uploadType=media", providerURL: gmail, contentType: "message/rfc822", body: "Subject: x\r\n\r\nhi"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			r := httptest.NewRequest(tc.method, tc.target, body)
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			if tc.alsoLabel != "" {
				r.Header.Add("Content-Type", tc.alsoLabel)
			}
			if tc.chunked {
				r.ContentLength = -1
			}
			status, err := Spec.RefuseRequest(r, tc.providerURL, defaultState())
			if tc.status == 0 {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tc.status, status)
			assert.ErrorIs(t, err, tc.err)
		})
	}
}

// Requests from the gateway are resolved then refused through the same state, so
// a host resolveUpstream will not address is one RefuseRequest turns away.
func TestResolveAndRefuseAgree(t *testing.T) {
	for _, target := range []string{
		gw + "/storage.googleapis.com/storage/v1/b",
		gw + "/evil.example.com/x",
		gw + "/gmail.googleapis.com:443/x",
	} {
		d, _ := resolveUpstream(httptest.NewRequest("GET", target, nil), "", defaultState())
		assert.Empty(t, d.UpstreamURL, target)
		status, err := refuse(t, target, d.UpstreamURL, nil)
		require.Error(t, err, target)
		assert.GreaterOrEqual(t, status, 400, target)
	}
}

// The body check skips exactly the requests whose body core does not parse, so no
// unread body reaches Google and no body core read is refused for being media.
func TestBodyCheckFollowsBodyParsing(t *testing.T) {
	for _, api := range []string{
		"/www.googleapis.com/upload/drive/v3/files",
		"/www.googleapis.com/UPLOAD/drive/v3/files",
		"/www.googleapis.com//upload/drive/v3/files",
		"/www.googleapis.com/%5Cupload/drive/v3/files",
		"/www.googleapis.com/upload;x/drive/v3/files",
		"/gmail.googleapis.com/resumable/upload/gmail/v1/users/me/messages/send",
		"/www.googleapis.com/drive/v3/files",
		"/www.googleapis.com/drive/v3/upload",
		"/www.googleapis.com/resumable/drive/v3/files",
	} {
		r := httptest.NewRequest("POST", gw+api, strings.NewReader("x"))
		r.Header.Set("Content-Type", "text/plain")
		d, _ := resolveUpstream(r, "", defaultState())
		require.NotEmpty(t, d.UpstreamURL, api)
		_, err := Spec.RefuseRequest(r, d.UpstreamURL, defaultState())
		assert.Equal(t, !d.BypassBodyParsing, errors.Is(err, errBodyNotJSON), api)
	}
}

func TestExtractGoogleToken(t *testing.T) {
	for _, typ := range []string{credential.TypeGCPDelegatedToken, credential.TypeGCPAccessToken} {
		h, err := extractGoogleToken(&logical.Request{Credential: &credential.Credential{
			Type: typ, Data: map[string]string{"access_token": "ya29.t"},
		}})
		require.NoError(t, err, typ)
		assert.Equal(t, map[string]string{"Authorization": "Bearer ya29.t"}, h)
	}

	for _, cred := range []*credential.Credential{
		nil,
		{Type: credential.TypeOAuthBearerToken, Data: map[string]string{"api_key": "t"}},
		{Type: credential.TypeGCPDelegatedToken, Data: map[string]string{}},
	} {
		_, err := extractGoogleToken(&logical.Request{Credential: cred})
		assert.Error(t, err)
	}
}

// A method override would have Google run a method policy did not authorize; an
// API key or billing project would ride on the user's token.
func TestHeadersStripped(t *testing.T) {
	h := http.Header{}
	for _, name := range []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override", "X-Goog-Api-Key", "X-Goog-User-Project"} {
		h.Set(name, "x")
	}
	h.Set("X-Goog-Upload-Protocol", "resumable")
	Spec.StripInboundHeaders(h)
	assert.Equal(t, http.Header{"X-Goog-Upload-Protocol": {"resumable"}}, h,
		"only the upload protocol, which uploads need, is left")
}

func TestHostAllowlistConfig(t *testing.T) {
	entries, err := parseAllowlist([]any{".gmail.googleapis.com", ".WWW.googleapis.com"})
	require.NoError(t, err)
	assert.Equal(t, []string{".gmail.googleapis.com", ".www.googleapis.com"}, entries)

	_, err = parseAllowlist(".googleapis.com")
	assert.NoError(t, err, "every Google API host is a choice the operator may make")

	for _, bad := range []any{".example.com", "gmail.googleapis.com", ".googleapis.com.evil.test", []any{1}} {
		_, err := parseAllowlist(bad)
		assert.Error(t, err, "%v", bad)
	}

	assert.Equal(t, defaultAllowedHostSuffixes, allowlist(defaultState()))
	assert.Equal(t, defaultAllowedHostSuffixes, allowlist(map[string]any{framework.HostAllowlistKey: []string{}}),
		"an empty list restores the default")
	assert.Equal(t, []string{}, configuredAllowlist(defaultState()))

	assert.Error(t, Spec.ValidateExtraConfig(map[string]any{framework.HostAllowlistKey: ".example.com"}))
	assert.NoError(t, Spec.ValidateExtraConfig(map[string]any{framework.HostAllowlistKey: ".gmail.googleapis.com"}))

	// Written, persisted as JSON, read back at the next start.
	written := map[string]any{framework.HostAllowlistKey: []string{".gmail.googleapis.com"}}
	stored, err := json.Marshal(Spec.OnConfigRead(written))
	require.NoError(t, err)
	var reloaded map[string]any
	require.NoError(t, json.Unmarshal(stored, &reloaded))
	state := Spec.OnInitialize(reloaded, map[string]any{})
	assert.Equal(t, []string{".gmail.googleapis.com"}, allowlist(state))
	state = Spec.OnInitialize(map[string]any{framework.HostAllowlistKey: []any{".example.com"}}, map[string]any{})
	assert.Equal(t, defaultAllowedHostSuffixes, allowlist(state), "a stored list that no longer parses falls back to the default")
}

// The stand-in upstream is accepted only where the build allows it.
func TestOverrideURL(t *testing.T) {
	assert.Error(t, checkOverrideURL("https://127.0.0.1:8443", nil), "no build hosts: refused")

	allowed := []string{"127.0.0.1", "localhost"}
	assert.NoError(t, checkOverrideURL("https://127.0.0.1:8443", allowed))
	assert.NoError(t, checkOverrideURL("https://localhost/", allowed))
	for _, bad := range []string{"http://127.0.0.1", "https://evil.test", "https://127.0.0.1/x", "https://u@127.0.0.1", "https://127.0.0.1?a=1"} {
		assert.Error(t, checkOverrideURL(bad, allowed), bad)
	}

	e2e := newSpec(allowed)
	status, err := e2e.RefuseRequest(httptest.NewRequest("GET", gw+"/gmail.googleapis.com/gmail/v1/x", nil), "https://127.0.0.1:8443", defaultState())
	assert.NoError(t, err, "status %d", status)
}

func TestRenderGoogleError(t *testing.T) {
	tests := []struct {
		f      *logical.GatewayFailure
		status string
		reason string
	}{
		{&logical.GatewayFailure{Status: 401, Err: fmt.Errorf("x: %w", credential.ErrUserRequired)}, "UNAUTHENTICATED", "authError"},
		{&logical.GatewayFailure{Status: 401, Err: credential.ErrUserChallenge}, "UNAUTHENTICATED", "authError"},
		{&logical.GatewayFailure{Status: 400, Err: errBatchNotSupported}, "INVALID_ARGUMENT", "batchNotSupported"},
		{&logical.GatewayFailure{Status: 403, Err: errHostNotAllowed}, "PERMISSION_DENIED", "hostNotAllowed"},
		{&logical.GatewayFailure{Status: 403, Err: fmt.Errorf("x: %w", credential.ErrUserNotAllowed)}, "PERMISSION_DENIED", "userNotAllowed"},
		{&logical.GatewayFailure{Status: 501, Err: errUploadNotRoutable}, "UNIMPLEMENTED", "uploadNotRoutable"},
		{&logical.GatewayFailure{Status: 400, Err: errCredentialInQuery}, "INVALID_ARGUMENT", "credentialInQuery"},
		{&logical.GatewayFailure{Status: 415, Err: errBodyNotJSON}, "INVALID_ARGUMENT", "unsupportedMediaType"},
		{&logical.GatewayFailure{Status: 400, Err: errBodyOnRead}, "INVALID_ARGUMENT", "bodyNotAllowed"},
		{&logical.GatewayFailure{Status: 403, Err: errors.New("denied")}, "PERMISSION_DENIED", "forbidden"},
		{&logical.GatewayFailure{Status: 404, Err: errors.New("x")}, "NOT_FOUND", "notFound"},
		{&logical.GatewayFailure{Status: 413, Err: errors.New("x")}, "INVALID_ARGUMENT", "uploadTooLarge"},
		{&logical.GatewayFailure{Status: 429, Err: errors.New("x")}, "RESOURCE_EXHAUSTED", "rateLimitExceeded"},
		{&logical.GatewayFailure{Status: 400, Err: errors.New("x")}, "INVALID_ARGUMENT", "badRequest"},
		{&logical.GatewayFailure{Status: 503, Err: errors.New("x")}, "UNAVAILABLE", "backendError"},
		{&logical.GatewayFailure{Status: 504, Err: errors.New("x")}, "DEADLINE_EXCEEDED", "backendError"},
	}
	for _, tc := range tests {
		t.Run(tc.status+"/"+tc.reason, func(t *testing.T) {
			// Classed as the gateway classes a failure; the proxy's own 502 and
			// 504 arrive classed unavailable.
			tc.f.Class = logical.ClassifyGatewayFailure(tc.f.Status, tc.f.Err)
			if tc.f.Status == http.StatusBadGateway || tc.f.Status == http.StatusGatewayTimeout {
				tc.f.Class = logical.GatewayFailureUnavailable
			}
			resp := renderGoogleError(nil, tc.f)
			assert.Equal(t, tc.f.Status, resp.StatusCode, "the status is Warden's")
			assert.Empty(t, resp.Headers.Get("WWW-Authenticate"), "core attaches the challenge")
			var body googleErrorBody
			require.NoError(t, json.Unmarshal(resp.Body, &body))
			assert.Equal(t, tc.f.Status, body.Error.Code)
			assert.Equal(t, tc.status, body.Error.Status)
			require.Len(t, body.Error.Errors, 1)
			assert.Equal(t, tc.reason, body.Error.Errors[0].Reason)
			assert.Equal(t, "global", body.Error.Errors[0].Domain)
			assert.True(t, strings.HasPrefix(body.Error.Message, "Warden: "))
		})
	}

	// A failure on Warden's side is INTERNAL whatever its status.
	status, reason := googleStatus(&logical.GatewayFailure{Status: 401, Class: logical.GatewayFailureInternal, Err: errors.New("x")})
	assert.Equal(t, "INTERNAL", status)
	assert.Equal(t, "internalError", reason)
}

// A request through the whole proxy, against a stand-in for Google: the user's
// token replaces the client's, refused headers are gone, a refusal is answered
// before anything is sent, and an upload session comes back pointing at Warden.
func TestGateway_ThroughTheProxy(t *testing.T) {
	type seen struct{ path, query, auth, override string }
	var mu sync.Mutex
	var got []seen
	stub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, seen{r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), r.Header.Get("X-HTTP-Method-Override")})
		mu.Unlock()
		if strings.Contains(r.URL.Path, "/upload/") {
			w.Header().Set("Location", "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=s1")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer stub.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	b, err := httpproxy.NewFactory(newSpec([]string{"127.0.0.1"}))(context.Background(), &logical.BackendConfig{
		Logger:          log,
		Config:          map[string]any{urlConfigKey: stub.URL, "tls_skip_verify": true},
		ExternalBaseURL: func(context.Context) string { return "https://warden.example.com" },
	})
	require.NoError(t, err)

	call := func(method, rel string, header http.Header) *httptest.ResponseRecorder {
		t.Helper()
		ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
		r := httptest.NewRequest(method, "/v1/gws/"+rel, nil).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer the-users-warden-token")
		for k, v := range header {
			r.Header[k] = v
		}
		rec := httptest.NewRecorder()
		_, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation, Path: rel, Streamed: true,
			HTTPRequest: r, ResponseWriter: rec, MountPoint: "gws/", AuditPath: rel,
			Credential: &credential.Credential{
				Type: credential.TypeGCPDelegatedToken, Data: map[string]string{"access_token": "ya29.user"},
			},
		})
		require.NoError(t, err)
		return rec
	}

	rec := call("GET", "role/ws/gateway/gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=5",
		http.Header{"X-Http-Method-Override": {"DELETE"}})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Len(t, got, 1)
	assert.Equal(t, seen{
		path: "/gmail.googleapis.com/gmail/v1/users/me/messages", query: "maxResults=5",
		auth: "Bearer ya29.user",
	}, got[0], "the stand-in sees the host segment, the user's token and no override")

	rec = call("GET", "role/ws/gateway/www.googleapis.com/batch/drive/v3", nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), `"reason":"batchNotSupported"`)
	assert.Len(t, got, 1, "a refusal reaches nothing")

	rec = call("POST", "role/ws/gateway/www.googleapis.com/upload/drive/v3/files?uploadType=resumable", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t,
		"https://warden.example.com/v1/gws/role/ws/gateway/www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=s1",
		rec.Header().Get("Location"))
}

func TestSpecIsValid(t *testing.T) {
	require.NoError(t, httpproxy.ValidateSpec(Spec))
	assert.True(t, Spec.RewriteWithoutPrefix, "an upload session that cannot be routed back is refused, not handed out")
}

func TestSkill(t *testing.T) {
	md := Skill()
	assert.True(t, strings.HasPrefix(md, "---\nname: gws\n"), "the skill name is the provider type")
	assert.Contains(t, md, "\nprovider: gws\n")
	assert.Contains(t, md, "\ncategory: provider-guide\n")
}
