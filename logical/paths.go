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

	// Stream is a list of paths that handle streaming requests.
	// For these paths, the core does two things during processing :
	// 	1) does NOT parse request body into req.Data
	// 	2) mints and injects credential into logical request
	// The path syntax is the same as Root and Unauthenticated:
	// exact match, or prefix match if ends with '*'.
	Stream []string
}






