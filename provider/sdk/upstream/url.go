// Package upstream builds the URL a gateway request is forwarded to.
//
// The path a request is authorized on is the decoded request path. Forwarding
// must send that same path, re-escaped, and nothing else. Concatenating it into
// a string and parsing the string again decodes it a second time: a client that
// sends "%252e%252e" is authorized on a literal "%2e%2e" segment and the
// upstream receives "%2e%2e", which it may resolve as "..". Every gateway that
// forwards a request path builds its URL here.
package upstream

import (
	"fmt"
	"net/url"
)

// URL returns base with path appended and rawQuery as its query. base is the
// operator's configured upstream ("https://api.example.com" or one with a path
// such as "https://mcp.example.com/mcp"), parsed once; its own escaping is
// kept. path is a decoded request path: it is appended exactly as given and
// escaped once on the wire, never decoded again.
//
// The result's path is base's path followed by path, with no slash added or
// removed, so ".../gateway" and ".../gateway/" still reach different upstream
// paths.
func URL(base, path, rawQuery string) (*url.URL, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid upstream URL %q: scheme and host are required", base)
	}
	escaped := u.EscapedPath() + (&url.URL{Path: path}).EscapedPath()
	u.Path += path
	// Kept only while it is a valid encoding of Path; net/url falls back to
	// escaping Path itself otherwise.
	u.RawPath = escaped
	u.RawQuery = rawQuery
	u.Fragment, u.RawFragment = "", ""
	return u, nil
}
