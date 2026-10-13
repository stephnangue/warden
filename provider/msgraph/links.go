package msgraph

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// Graph answers a long listing one page at a time, with the next page — and a
// delta query's next round — as an absolute URL on Graph itself. An SDK follows
// it verbatim, straight to Graph and without the token Warden injects, so the
// call fails. The links are rewritten onto the gateway instead.

const stateRewriteLinks = "rewrite_links"

// defaultResponseCap bounds the buffered body when the mount sets no cap.
const defaultResponseCap = framework.DefaultMaxBodySize

var linkConfigFields = map[string]*framework.FieldSchema{
	stateRewriteLinks: {
		Type:    framework.TypeBool,
		Default: true,
		Description: "Rewrite Graph's @odata.nextLink and @odata.deltaLink onto this gateway so clients page " +
			"through Warden (default true). Needs the protected-resource resource_url; costs uncompressed listings",
	},
}

func rewriteLinksEnabled(state map[string]any) bool {
	v, ok := state[stateRewriteLinks].(bool)
	return !ok || v
}

// rewriteRequested rewrites listings: GET, the only method Graph pages.
func rewriteRequested(r *http.Request, state map[string]any) bool {
	return r.Method == http.MethodGet && rewriteLinksEnabled(state)
}

// rewriteLinks rewrites the paging links in a Graph JSON response onto the
// gateway. Only properties named @odata.nextLink or @odata.deltaLink — on their
// own or qualified, as in members@odata.nextLink — at the top level of the body
// are touched, and only when they point at the Graph origin the request went to.
// Anything else passes through byte for byte.
//
// It fails open: a body over the cap, not JSON, or unreadable is forwarded as
// received, with nothing lost, since a link left pointing at Graph only costs
// the client a rewrite of its own.
func rewriteLinks(resp *http.Response, rc httpproxy.RewriteContext) error {
	// Only GETs get here (rewriteRequested), so there is no HEAD to guard against.
	if resp.StatusCode < 200 || resp.StatusCode > 299 || resp.Request == nil ||
		resp.Body == nil || resp.Body == http.NoBody {
		return nil
	}
	if resp.Header.Get("Content-Encoding") != "" {
		return nil // Accept-Encoding was dropped; an encoded body is not one to rewrite.
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return nil
	}
	origin := resp.Request.URL.Scheme + "://" + resp.Request.URL.Host
	if resp.Request.URL.Scheme == "" || resp.Request.URL.Host == "" {
		return nil
	}

	limit := rc.MaxBodySize
	if limit <= 0 {
		limit = defaultResponseCap
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(buf)) > limit {
		// Forward what was read, then the rest, untouched.
		resp.Body = readCloser{io.MultiReader(bytes.NewReader(buf), resp.Body), resp.Body}
		return nil
	}
	resp.Body.Close()

	out, changed := rewriteODataLinks(buf, origin, rc.Prefix)
	if !changed {
		resp.Body = io.NopCloser(bytes.NewReader(buf))
		return nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	resp.TransferEncoding = nil
	resp.Header.Del("Transfer-Encoding")
	return nil
}

type readCloser struct {
	io.Reader
	io.Closer
}

func isPagingLinkKey(key string) bool {
	return strings.HasSuffix(key, "@odata.nextLink") || strings.HasSuffix(key, "@odata.deltaLink")
}

// rewriteODataLinks returns body with its top-level paging links rewritten from
// origin onto prefix, and whether anything changed. A body that is not a JSON
// object, or holds no such link, is reported unchanged.
func rewriteODataLinks(body []byte, origin, prefix string) ([]byte, bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, false
	}
	changed := false
	lowerOrigin := strings.ToLower(origin) + "/"
	for key, raw := range obj {
		if !isPagingLinkKey(key) {
			continue
		}
		var link string
		if err := json.Unmarshal(raw, &link); err != nil {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(link), lowerOrigin) {
			continue
		}
		rewritten, err := marshalNoEscape(prefix + link[len(origin):])
		if err != nil {
			continue
		}
		obj[key] = rewritten
		changed = true
	}
	if !changed {
		return nil, false
	}
	// The re-marshal compacts every value and copies the body once more; only a
	// page that carried a link pays it, and the page is bounded by max_body_size.
	out, err := marshalNoEscape(obj)
	if err != nil {
		return nil, false
	}
	return out, true
}

// marshalNoEscape is json.Marshal without HTML escaping, so the & in a query
// string stays readable.
func marshalNoEscape(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}
