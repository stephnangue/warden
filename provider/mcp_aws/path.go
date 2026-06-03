package mcp_aws

import "strings"

// pathAfterGateway returns the substring of reqPath that follows the first
// "gateway" segment, with that segment dropped. Trailing slashes are
// preserved verbatim — MCP servers distinguish "/mcp" from "/mcp/" and
// re-normalizing them would invalidate the SigV4 canonical request.
//
// Accepts both forms encountered in the request pipeline:
//
//   - Absolute paths (e.g. "/v1/team-data/mcp_aws/role/s3-reader/gateway/tools/call")
//     as seen on req.HTTPRequest.URL.Path
//   - Mount-relative paths (e.g. "gateway", "role/s3-reader/gateway/tools/call")
//     as seen on req.Path after the framework strips the mount prefix
//
// Returns "" when reqPath has no "gateway" segment (caller should treat that
// as a programmer error — the path patterns registered with the framework
// guarantee a gateway segment is present).
func pathAfterGateway(reqPath string) string {
	if i := strings.Index(reqPath, "/gateway"); i >= 0 {
		return reqPath[i+len("/gateway"):]
	}
	if strings.HasPrefix(reqPath, "gateway") {
		return reqPath[len("gateway"):]
	}
	return ""
}
