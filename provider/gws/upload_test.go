package gws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

const testPrefix = "https://warden.example.com/v1/gws/role/ws/gateway"

// forwarded is a request as the gateway forwards it: its URL Google's.
func forwarded(method, url string, header http.Header) *http.Request {
	r := httptest.NewRequest(method, url, nil)
	for k, v := range header {
		r.Header[k] = v
	}
	return r
}

// Every request to an upload path is watched: which method opens a session and
// how the resumable protocol is spelled are Google's, and the response says
// whether one opened.
func TestUploadRequest(t *testing.T) {
	resumable := http.Header{"X-Goog-Upload-Protocol": {"resumable"}}
	tests := []struct {
		name  string
		r     *http.Request
		opens bool
	}{
		{"drive resumable", forwarded("POST", "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable", nil), true},
		{"an update opens one too", forwarded("PATCH", "https://www.googleapis.com/upload/drive/v3/files/abc?uploadType=resumable", nil), true},
		{"a chunk", forwarded("PUT", "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=x", nil), true},
		{"the protocol spelled otherwise", forwarded("POST", "https://www.googleapis.com/upload/drive/v3/files?upload_protocol=resumable", nil), true},
		{"the protocol encoded", forwarded("POST", "https://www.googleapis.com/upload/drive/v3/files?uploadType=resum%61ble", nil), true},
		{"gmail's resumable path", forwarded("POST", "https://gmail.googleapis.com/resumable/upload/gmail/v1/users/me/messages/send", nil), true},
		{"the upload protocol header", forwarded("POST", "https://www.googleapis.com/upload/drive/v3/files", resumable), true},
		{"in capitals", forwarded("POST", "https://www.googleapis.com/UPLOAD/drive/v3/files?uploadType=resumable", nil), true},
		{"with parameters", forwarded("POST", "https://www.googleapis.com/upload;x=1/drive/v3/files?uploadType=resumable", nil), true},
		{"through the e2e stand-in", forwarded("POST", "https://127.0.0.1:8443/www.googleapis.com/upload/drive/v3/files?uploadType=resumable", nil), true},
		{"not an upload path", forwarded("POST", "https://www.googleapis.com/drive/v3/files?uploadType=resumable", nil), false},
		{"upload deeper in the path", forwarded("POST", "https://www.googleapis.com/drive/v3/upload/x", nil), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.opens, uploadRequest(tc.r, nil))
		})
	}
}

func sessionResponse(status int, header http.Header) *http.Response {
	h := http.Header{}
	for k, v := range header {
		h[k] = v
	}
	return &http.Response{
		StatusCode: status, Header: h,
		Body:    io.NopCloser(strings.NewReader("")),
		Request: forwarded("POST", "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable", nil),
	}
}

func TestRewriteUploadSession(t *testing.T) {
	const session = "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=xa298sd_sdlkj2"

	t.Run("onto the gateway", func(t *testing.T) {
		resp := sessionResponse(200, http.Header{
			"Location":                  {session},
			"X-Goog-Upload-Url":         {session},
			"X-Goog-Upload-Control-Url": {session},
		})
		require.NoError(t, rewriteUploadSession(resp, httpproxy.RewriteContext{Prefix: testPrefix}))
		want := testPrefix + "/www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=xa298sd_sdlkj2"
		assert.Equal(t, want, resp.Header.Get("Location"), "host segment and query kept byte for byte")
		assert.Equal(t, want, resp.Header.Get("X-Goog-Upload-URL"))
		assert.Equal(t, want, resp.Header.Get("X-Goog-Upload-Control-URL"))
		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("a chunk still owed passes as it came", func(t *testing.T) {
		resp := sessionResponse(308, http.Header{"Range": {"bytes=0-262143"}})
		require.NoError(t, rewriteUploadSession(resp, httpproxy.RewriteContext{}))
		assert.Equal(t, 308, resp.StatusCode)
		assert.Equal(t, "bytes=0-262143", resp.Header.Get("Range"))
	})

	t.Run("another host is rewritten too, and checked when used", func(t *testing.T) {
		resp := sessionResponse(200, http.Header{"Location": {"https://gmail.googleapis.com/upload/gmail/v1/x?upload_id=1"}})
		require.NoError(t, rewriteUploadSession(resp, httpproxy.RewriteContext{Prefix: testPrefix}))
		assert.Equal(t, testPrefix+"/gmail.googleapis.com/upload/gmail/v1/x?upload_id=1", resp.Header.Get("Location"))
	})

	t.Run("no session, nothing to do", func(t *testing.T) {
		resp := sessionResponse(200, nil)
		require.NoError(t, rewriteUploadSession(resp, httpproxy.RewriteContext{}))
		assert.Equal(t, 200, resp.StatusCode, "a chunk's answer passes even with no external address")
	})

	t.Run("a refusal from Google passes as it came", func(t *testing.T) {
		resp := sessionResponse(403, http.Header{"Location": {session}})
		require.NoError(t, rewriteUploadSession(resp, httpproxy.RewriteContext{}))
		assert.Equal(t, 403, resp.StatusCode)
	})

	for name, tc := range map[string]struct {
		prefix, uri string
	}{
		"no external address": {"", session},
		"a port":              {testPrefix, "https://www.googleapis.com:8443/upload/x"},
		"credentials":         {testPrefix, "https://u@www.googleapis.com/upload/x"},
		"plain http":          {testPrefix, "http://www.googleapis.com/upload/x"},
		"an IP literal":       {testPrefix, "https://10.0.0.1/upload/x"},
		"no path":             {testPrefix, "https://www.googleapis.com?upload_id=1"},
	} {
		t.Run("refused: "+name, func(t *testing.T) {
			resp := sessionResponse(200, http.Header{
				"Location":             {tc.uri},
				"X-Guploader-Uploadid": {"xa298sd_sdlkj2"},
			})
			require.NoError(t, rewriteUploadSession(resp, httpproxy.RewriteContext{Prefix: tc.prefix}))
			assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "not a status client libraries retry into more sessions")
			assert.Empty(t, resp.Header.Get("Location"), "Google's session URI is never handed out")
			assert.Empty(t, resp.Header.Get("X-Guploader-Uploadid"), "nor anything else Google sent")
			var body googleErrorBody
			raw, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(raw, &body))
			assert.Equal(t, "uploadNotRoutable", body.Error.Errors[0].Reason)
			assert.Equal(t, "UNIMPLEMENTED", body.Error.Status)
			assert.Equal(t, int64(len(raw)), resp.ContentLength)
			assert.Nil(t, resp.Trailer)
		})
	}
}
