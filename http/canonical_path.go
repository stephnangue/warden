package http

import "strings"

// errNonCanonicalPath is the answer to a request path canonicalRequestPath
// refuses.
const errNonCanonicalPath = `request path must not contain "." or ".." segments or empty segments`

// canonicalRequestPath reports whether p, a decoded request path under "/v1/",
// spells each segment once: no "." or ".." segment, and no empty segment but a
// single trailing one (so a list's "foo/" and a gateway's ".../gateway/" keep
// their meaning).
//
// The router redirects a literal "/../", "/./" or "//" to the clean path
// before any handler runs, so only a percent-encoded spelling ("%2e%2e",
// "%2e", "%2F") reaches one, decoded and intact; the caller checks only a path
// that arrived encoded. Policies are matched against the path as it stands,
// while a gateway forwards it to an upstream that may resolve the dot segment
// or merge the slashes: a deny on "repos/org/secret*" beside a grant on
// "repos/org/*" would not see ".../public/%2e%2e/secret". Such a path names a
// resource only by another spelling, so it is refused rather than cleaned.
//
// A dot inside or leading a segment (".github", "repo.git") is ordinary, as is
// an encoded slash inside one, which some upstreams' identifiers need.
//
// It runs on every request: one pass over p, no allocation.
func canonicalRequestPath(p string) bool {
	rest := strings.TrimPrefix(p, "/v1/")
	for rest != "" {
		seg, tail, more := strings.Cut(rest, "/")
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		if !more {
			break
		}
		rest = tail
	}
	return true
}
