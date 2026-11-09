// Package graphbatch recognises Microsoft Graph's JSON batch endpoint.
//
// A $batch request carries up to twenty sub-requests in its body, each with its
// own method and path, so it would let a caller reach any path through one that a
// path policy allows. Warden does not authorise sub-requests, so providers that
// front Graph refuse the endpoint outright, and use this to recognise it.
package graphbatch

import (
	"path"
	"strings"
)

// segment is the batch endpoint's path segment.
const segment = "$batch"

// hosts are the Microsoft Graph endpoints of the public and sovereign clouds.
var hosts = []string{
	"graph.microsoft.com",
	"graph.microsoft.us",
	"dod-graph.microsoft.us",
	"microsoftgraph.chinacloudapi.cn",
}

// Hosts returns the Microsoft Graph endpoints of the public and sovereign clouds.
// The slice is a copy; callers may keep or change it.
func Hosts() []string {
	return append([]string(nil), hosts...)
}

// IsGraphHost reports whether host (no port, any case) is a Microsoft Graph
// endpoint or a name under one.
func IsGraphHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range hosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

// IsBatchPath reports whether an API path — the part of a gateway path after
// "/gateway", already percent-decoded as net/url decodes it — addresses the batch
// endpoint in any spelling: any version, any case, behind dot segments or repeated
// slashes, with or without a trailing slash. Graph has no other resource named
// $batch, so any segment that matches is refused rather than only the canonical
// /v1.0/$batch.
//
// A backslash counts as a separator and a segment's ;parameters are ignored:
// front ends that normalise either would otherwise turn "v1.0\$batch" or
// "$batch;x=1" into the batch endpoint past this check.
func IsBatchPath(p string) bool {
	p = strings.ReplaceAll(p, `\`, "/")
	for _, seg := range strings.Split(path.Clean("/"+p), "/") {
		if i := strings.IndexByte(seg, ';'); i >= 0 {
			seg = seg[:i]
		}
		if strings.EqualFold(seg, segment) {
			return true
		}
	}
	return false
}
