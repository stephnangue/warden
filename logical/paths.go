package logical

// Paths extends sdklogical.Paths with warden-specific path types.
// It contains categorizations of paths for special handling by the router.
type Paths struct {
	// Root are the API paths that require a root token to access
	Root []string

	// Unauthenticated are the API paths that can be accessed without any auth.
	// These can't be regular expressions, it is either exact match, a prefix
	// match and/or a wildcard match. For prefix match, append '*' as a suffix.
	// For a wildcard match, use '+' in the segment to match any identifier
	// (e.g. 'foo/+/bar'). Note that '+' can't be adjacent to a non-slash.
	Unauthenticated []string

	// Stream are the paths whose backend reads the raw request body and writes
	// the HTTP response itself, through req.ResponseWriter, returning a
	// Response with Streamed set: a gateway proxying to an upstream, or a
	// server answering in its own wire format. For these paths the core:
	//  1) does NOT parse the body into req.Data, unless the backend implements
	//     StreamBodyParser and returns true from ShouldParseStreamBody; then
	//     JSON and form-urlencoded bodies are parsed and restored for the
	//     handler to re-read;
	//  2) sheds the listener's write deadline for the whole request, and bounds
	//     the body read with a window that closes once the body is in hand, so
	//     the response may stream for as long as the backend allows;
	//  3) buffers and strict-parses a JSON-RPC body for a backend that
	//     implements MCPPolicyEnforced, so the MCP policy gate decides on it
	//     before routing;
	//  4) takes the credential from the request through the backend
	//     (ExtractTokens), which may admit it implicitly as a gateway does;
	//  5) on a gateway request, mints the role's credential and injects it into
	//     the request. A request with no role to mint for, on an Identity path
	//     or a backend's unauthenticated stream, mints nothing.
	// The path syntax is the same as Root and Unauthenticated:
	// exact match, or prefix match if ends with '*'.
	Stream []string

	// Identity are the paths that authorize on the credential the caller
	// presents, before any role is chosen. A request to one carries no role:
	// a role selection is ignored and nothing is minted. Without a service
	// token it runs under the namespace's built-in policies alone; with one,
	// under that token's policies and the built-ins. Only the system backend
	// may declare them, and none may also be Root or Unauthenticated. The
	// syntax is that of Root.
	Identity []string
}
