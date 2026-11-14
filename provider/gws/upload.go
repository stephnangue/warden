package gws

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// A resumable upload starts with a request that returns a session URI, in the
// Location header (or X-Goog-Upload-URL), on a googleapis.com host; the client
// then sends the file to that URI in chunks. Left as Google wrote it, a client
// library sends the chunks — and with them the Authorization header it holds,
// the user's credential for Warden — straight to Google, and Warden sees none of
// them. So the URI is pointed back at the gateway, host segment and all, and a
// session that cannot be is refused rather than handed out.
//
// This steers a client that follows the URI it is given; it is not a boundary.
// The session URI is its own credential at Google, so a client that strips the
// gateway prefix can still send the chunks there itself. What it uploads is the
// content of the one file whose creation policy authorized when the session
// was opened: the name, the parents, the account were all fixed then.

var errUploadNotRoutable = errors.New("Warden cannot route this upload session back through itself: " +
	"the protected-resource resource_url must be set, or upload in a single request (uploadType=multipart)")

// uploadSessionHeaders are where Google hands back a session URI or a URL that
// controls one.
var uploadSessionHeaders = []string{"Location", "X-Goog-Upload-URL", "X-Goog-Upload-Control-URL"}

// uploadRequest reports whether a request may open an upload session: any
// request to an upload path. Which method opens one (POST to create, PATCH or
// PUT to update) and how the resumable protocol is asked for (uploadType,
// upload_protocol, a header, encoded or not) are left to Google; the response
// says whether a session opened, and rewriteUploadSession acts only on that. r
// is the request as forwarded, its URL Google's.
func uploadRequest(r *http.Request, _ map[string]any) bool {
	return isUploadPath(forwardedAPIPath(r.URL.Path))
}

// forwardedAPIPath is the Google API path of a forwarded request. Against the
// end-to-end stand-in the host segment is still first; a Google API path's own
// first segment never holds a dot, so a dotted one is that host.
func forwardedAPIPath(p string) string {
	host, rest := splitHost(p)
	if strings.Contains(host, ".") {
		return rest
	}
	return p
}

// rewriteUploadSession points a session URI Google returned back at the gateway.
// Only a success can open a session; any other answer is left as it came. With no
// prefix to rewrite onto, or a URI it cannot read as https://<host>/<path>, the
// response is replaced by a refusal: the session is abandoned at Google, unused,
// and expires there.
func rewriteUploadSession(resp *http.Response, rc httpproxy.RewriteContext) error {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil
	}
	for _, name := range uploadSessionHeaders {
		uri := resp.Header.Get(name)
		if uri == "" {
			continue
		}
		rewritten, ok := gatewaySessionURL(uri, rc.Prefix)
		if !ok {
			refuseUpload(resp)
			return nil
		}
		resp.Header.Set(name, rewritten)
	}
	return nil
}

// gatewaySessionURL rewrites https://<host>/<path>?<query> to
// <prefix>/<host>/<path>?<query>. The path and query are kept byte for byte; the
// host must be a plain hostname, so a port, credentials or an IP literal fail.
// Whether the host is one the mount sends tokens to is checked when the client
// uses the URI, as for any request.
func gatewaySessionURL(uri, prefix string) (string, bool) {
	if prefix == "" {
		return "", false
	}
	rest, ok := strings.CutPrefix(uri, "https://")
	if !ok {
		return "", false
	}
	end := strings.IndexAny(rest, "/?#")
	if end <= 0 || rest[end] != '/' {
		return "", false
	}
	host := rest[:end]
	if framework.ValidateTargetHost(host) != nil {
		return "", false
	}
	return prefix + "/" + rest, true
}

// refuseUpload replaces a response that opened a session with Warden's refusal.
// Every upstream header goes, the session's included. The status is 501, which
// client libraries do not retry: the mount cannot serve resumable uploads until
// its configuration changes, and each retry would open another session.
func refuseUpload(resp *http.Response) {
	refusal := renderGoogleError(resp.Request, &logical.GatewayFailure{
		Class:  logical.GatewayFailureInternal,
		Status: http.StatusNotImplemented,
		Err:    errUploadNotRoutable,
	})
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	resp.StatusCode = refusal.StatusCode
	resp.Status = strconv.Itoa(refusal.StatusCode) + " " + http.StatusText(refusal.StatusCode)
	resp.Header = refusal.Headers.Clone()
	resp.Header.Set("Content-Length", strconv.Itoa(len(refusal.Body)))
	resp.ContentLength = int64(len(refusal.Body))
	resp.TransferEncoding = nil
	resp.Trailer = nil
	resp.Body = io.NopCloser(bytes.NewReader(refusal.Body))
}
