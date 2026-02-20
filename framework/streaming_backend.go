// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Customized for warden to support streaming/proxy backends

package framework

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-radix"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// Default values for common provider fields
const (
	DefaultMaxBodySize = int64(10485760) // 10MB
	DefaultTimeout     = 30 * time.Second
)

// DefaultTransparentRolePattern is the default pattern for extracting role from transparent paths.
// Matches: role/{role}/gateway... and extracts the role name.
var DefaultTransparentRolePattern = regexp.MustCompile(`^role/([^/]+)/gateway`)

// DefaultPathRewriter rewrites transparent paths to standard paths.
// Converts: role/X/gateway/... -> gateway/...
func DefaultPathRewriter(path string) string {
	return DefaultTransparentRolePattern.ReplaceAllString(path, "gateway")
}

// TransparentConfig holds declarative transparent mode configuration.
// Providers can set this to enable transparent mode without implementing
// the TransparentModeProvider interface manually.
type TransparentConfig struct {
	// Enabled indicates if transparent mode is available for this backend
	Enabled bool

	// AutoAuthPath is the auth mount path for implicit authentication (e.g., "auth/jwt/")
	AutoAuthPath string

	// DefaultRole is the role to use when not specified in URL path
	DefaultRole string

	// RolePattern is the regex pattern to extract role from path (optional)
	// If nil, uses DefaultTransparentRolePattern: `^role/([^/]+)/gateway`
	// First capture group is used as the role name
	RolePattern *regexp.Regexp

	// PathRewriter converts transparent paths to standard paths (optional)
	// If nil, uses DefaultPathRewriter: role/X/gateway/... -> gateway/...
	PathRewriter func(path string) string
}

// unauthPathsEntry holds parsed unauthenticated paths for efficient matching
type unauthPathsEntry struct {
	// paths is a radix tree for exact and prefix matches
	paths *radix.Tree
	// wildcardPaths holds patterns with + segment wildcards
	wildcardPaths []wildcardPath
}

// wildcardPath represents a path pattern with + segment wildcards
type wildcardPath struct {
	segments []string
	isPrefix bool
}

// StreamingOperationFunc handles streaming operations with raw HTTP access.
// It receives the context, the full logical.Request (which includes ResponseWriter,
// HTTPRequest, and Credential), and parsed field data.
// The function is responsible for writing the response directly to req.ResponseWriter.
type StreamingOperationFunc func(ctx context.Context, req *logical.Request, fd *FieldData) error

// StreamingPath represents a path that handles streaming requests.
// Unlike regular paths, streaming paths write directly to the HTTP response.
type StreamingPath struct {
	// Pattern is the regex pattern for matching this path
	Pattern string

	// Fields defines the expected fields for this path
	Fields map[string]*FieldSchema

	// Handler is the streaming operation handler
	Handler StreamingOperationFunc

	// HelpSynopsis is a brief description of this path
	HelpSynopsis string

	// HelpDescription is a longer description of this path
	HelpDescription string
}

// StreamingBackend implements logical.Backend for streaming/proxy operations.
// It combines streaming paths (for proxy operations) with regular framework paths
// (for configuration and management).
type StreamingBackend struct {
	// StreamingPaths are paths that handle streaming operations (e.g., gateway/*)
	StreamingPaths []*StreamingPath

	// TransparentConfig holds the transparent mode configuration (optional)
	// When set, StreamingBackend implements logical.TransparentModeProvider
	TransparentConfig *TransparentConfig

	// UnauthenticatedPaths are paths that can be accessed without authentication.
	// These are hardcoded by the provider for read-only endpoints that some clients
	// access without sending tokens (e.g., PKI certificate PEM files).
	// Supports: exact match, prefix match (*), segment wildcard (+)
	UnauthenticatedPaths []string

	// Backend is the embedded standard framework backend for non-streaming paths
	*Backend

	// MaxBodySize is the maximum request body size in bytes.
	MaxBodySize int64

	// Timeout is the request timeout duration.
	Timeout time.Duration

	// Proxy is the shared reverse proxy for streaming requests.
	// Initialized via InitProxy with a provider-specific transport.
	Proxy *httputil.ReverseProxy

	// Logger is the provider's scoped logger (set via conf.Logger.WithSubsystem).
	Logger *logger.GatedLogger

	// StorageView is the provider's storage backend for persisting configuration.
	StorageView sdklogical.Storage

	// Internal state
	streamingPathsRe []*regexp.Regexp
	streamingOnce    sync.Once

	// unauthPaths holds the parsed unauthenticated paths (radix tree + wildcards)
	unauthPaths     *unauthPathsEntry
	unauthPathsOnce sync.Once
}

// Ensure StreamingBackend implements logical.Backend
var _ logical.Backend = (*StreamingBackend)(nil)

// initStreaming initializes the streaming path regex patterns
func (b *StreamingBackend) initStreaming() {
	b.streamingPathsRe = make([]*regexp.Regexp, len(b.StreamingPaths))
	for i, p := range b.StreamingPaths {
		if len(p.Pattern) == 0 {
			panic("Streaming path pattern cannot be blank")
		}
		// Automatically anchor the pattern
		pattern := p.Pattern
		if pattern[0] != '^' {
			pattern = "^" + pattern
		}
		if pattern[len(pattern)-1] != '$' {
			pattern = pattern + "$"
		}
		b.streamingPathsRe[i] = regexp.MustCompile(pattern)
	}
}

// routeStreaming finds a matching streaming path for the given request path
func (b *StreamingBackend) routeStreaming(path string) (*StreamingPath, map[string]string) {
	b.streamingOnce.Do(b.initStreaming)

	for i, re := range b.streamingPathsRe {
		matches := re.FindStringSubmatch(path)
		if matches == nil {
			continue
		}

		var captures map[string]string
		streamingPath := b.StreamingPaths[i]
		if captureNames := re.SubexpNames(); len(captureNames) > 1 {
			captures = make(map[string]string, len(captureNames))
			for j, name := range captureNames {
				if name != "" {
					captures[name] = matches[j]
				}
			}
		}

		return streamingPath, captures
	}

	return nil, nil
}

// HandleRequest routes to either streaming or standard handling based on req.Streamed.
// If req.Streamed is true (set by core routing), it handles streaming directly.
// Otherwise, it falls back to the embedded Backend's HandleRequest.
func (b *StreamingBackend) HandleRequest(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	// Handle help operation for both streaming and regular paths.
	// Help requests are never streamed (core skips streaming flow for HelpOperation).
	if req.Operation == logical.HelpOperation {
		if req.Path == "" {
			return b.handleRootHelpWithStreaming(req)
		}
		// Check if path matches a streaming path
		streamingPath, _ := b.routeStreaming(req.Path)
		if streamingPath != nil {
			return streamingPathHelp(req, streamingPath)
		}
		// Fall through to Backend for regular path help
	}

	// Handle streaming requests (req.Streamed is set by core when path matches streaming paths)
	if req.Streamed && req.HTTPRequest != nil && req.ResponseWriter != nil {
		streamingPath, captures := b.routeStreaming(req.Path)
		if streamingPath != nil {
			err := b.handleStreaming(ctx, req, streamingPath, captures)
			if err != nil {
				return &logical.Response{
					StatusCode: http.StatusInternalServerError,
					Err:        err,
				}, nil
			}
			// Return response indicating streaming was handled
			return &logical.Response{Streamed: true}, nil
		}
	}

	// Fall back to standard Backend handling for config/management paths
	if b.Backend != nil {
		return b.Backend.HandleRequest(ctx, req)
	}

	return nil, sdklogical.ErrUnsupportedPath
}

// streamingPathHelp generates help text for a streaming path.
func streamingPathHelp(req *logical.Request, sp *StreamingPath) (*logical.Response, error) {
	var tplData pathTemplateData
	tplData.Request = req.Path
	tplData.RoutePattern = sp.Pattern
	tplData.Synopsis = strings.TrimSpace(sp.HelpSynopsis)
	if tplData.Synopsis == "" {
		tplData.Synopsis = "<no synopsis>"
	}
	tplData.Description = strings.TrimSpace(sp.HelpDescription)
	if tplData.Description == "" {
		tplData.Description = "<no description>"
	}

	// Build field help from streaming path fields
	fieldKeys := make([]string, 0, len(sp.Fields))
	for k := range sp.Fields {
		fieldKeys = append(fieldKeys, k)
	}
	sort.Strings(fieldKeys)

	tplData.Fields = make([]pathTemplateFieldData, len(fieldKeys))
	for i, k := range fieldKeys {
		schema := sp.Fields[k]
		description := strings.TrimSpace(schema.Description)
		if description == "" {
			description = "<no description>"
		}
		tplData.Fields[i] = pathTemplateFieldData{
			Key:         k,
			Type:        schema.Type.String(),
			Description: description,
			Deprecated:  schema.Deprecated,
		}
	}

	help, err := executeTemplate(pathHelpTemplate, &tplData)
	if err != nil {
		return nil, fmt.Errorf("error executing template: %w", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"help": help,
		},
	}, nil
}

// handleRootHelpWithStreaming generates root help that includes both regular and streaming paths.
func (b *StreamingBackend) handleRootHelpWithStreaming(req *logical.Request) (*logical.Response, error) {
	b.once.Do(b.init)
	b.streamingOnce.Do(b.initStreaming)

	// Collect regular paths
	pathsMap := make(map[string]string)
	allPaths := make([]string, 0)
	for i, p := range b.pathsRe {
		route := p.String()
		allPaths = append(allPaths, route)
		pathsMap[route] = strings.TrimSpace(b.Paths[i].HelpSynopsis)
	}

	// Collect streaming paths
	for _, sp := range b.StreamingPaths {
		pattern := sp.Pattern
		allPaths = append(allPaths, pattern)
		pathsMap[pattern] = strings.TrimSpace(sp.HelpSynopsis)
	}

	sort.Strings(allPaths)

	pathData := make([]rootHelpTemplatePath, 0, len(allPaths))
	for _, route := range allPaths {
		pathData = append(pathData, rootHelpTemplatePath{
			Path: route,
			Help: pathsMap[route],
		})
	}

	help, err := executeTemplate(rootHelpTemplate, &rootHelpTemplateData{
		Help:  strings.TrimSpace(b.Help),
		Paths: pathData,
	})
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"help": help,
		},
	}, nil
}

// handleStreaming executes the streaming path handler
func (b *StreamingBackend) handleStreaming(ctx context.Context, req *logical.Request, path *StreamingPath, captures map[string]string) error {
	// Build field data from request and captures
	raw := make(map[string]interface{})

	// Add captures from path regex
	for k, v := range captures {
		raw[k] = v
	}

	// Add query parameters
	for k, v := range req.HTTPRequest.URL.Query() {
		if len(v) == 1 {
			raw[k] = v[0]
		} else {
			raw[k] = v
		}
	}

	fd := &FieldData{
		Raw:    raw,
		Schema: path.Fields,
	}

	// Execute the streaming handler with the full logical.Request
	err := path.Handler(ctx, req, fd)

	// Auto-capture upstream URL for audit logging.
	// All providers rewrite req.HTTPRequest.URL to the upstream target before proxying,
	// so we can reliably derive it here as a safety net.
	if req.UpstreamURL == "" && req.HTTPRequest != nil && req.HTTPRequest.URL != nil {
		req.UpstreamURL = req.HTTPRequest.URL.String()
	}

	return err
}

// HandleExistenceCheck delegates to the embedded Backend
func (b *StreamingBackend) HandleExistenceCheck(ctx context.Context, req *logical.Request) (checkFound bool, exists bool, err error) {
	if b.Backend != nil {
		return b.Backend.HandleExistenceCheck(ctx, req)
	}
	return false, false, nil
}

// SpecialPaths returns special paths including streaming paths
func (b *StreamingBackend) SpecialPaths() *logical.Paths {
	// Get base paths from embedded Backend
	var basePaths *logical.Paths
	if b.Backend != nil {
		basePaths = b.Backend.SpecialPaths()
	}

	// Collect streaming path patterns
	streamPaths := make([]string, 0, len(b.StreamingPaths))
	for _, sp := range b.StreamingPaths {
		// Convert regex pattern to glob-style pattern for router
		// The router uses radix tree with literal prefix matching, so we need to:
		// - Convert ".*" suffix to "*" for prefix matching
		// - Handle patterns with [^/]+ by using prefix before wildcard
		// - Remove regex anchors
		//
		// NOTE: The radix tree doesn't support wildcards in the middle of paths.
		// For patterns like "role/[^/]+/gateway", we use "role/*" as a prefix match
		// to identify streaming requests. The actual pattern matching happens in
		// HandleRequest using the compiled regex patterns.
		pattern := sp.Pattern

		// Remove regex anchors if present
		pattern = strings.TrimPrefix(pattern, "^")
		pattern = strings.TrimSuffix(pattern, "$")

		// Handle patterns with [^/]+ (wildcard segment)
		// Use the prefix before the wildcard as a prefix match
		// e.g., "role/[^/]+/gateway" -> "role/*"
		if idx := strings.Index(pattern, "[^/]+"); idx >= 0 {
			pattern = pattern[:idx] + "*"
		} else if strings.HasSuffix(pattern, ".*") {
			// Convert .* suffix to * for prefix matching
			// e.g., "gateway/.*" -> "gateway/*"
			pattern = strings.TrimSuffix(pattern, ".*") + "*"
		}

		streamPaths = append(streamPaths, pattern)
	}

	if basePaths != nil {
		return &logical.Paths{
			Root:            basePaths.Root,
			Unauthenticated: basePaths.Unauthenticated,
			Stream:          streamPaths,
		}
	}

	return &logical.Paths{
		Stream: streamPaths,
	}
}

// Cleanup delegates to the embedded Backend
func (b *StreamingBackend) Cleanup(ctx context.Context) {
	if b.Backend != nil {
		b.Backend.Cleanup(ctx)
	}
}

// Setup delegates to the embedded Backend
func (b *StreamingBackend) Setup(ctx context.Context, config *logical.BackendConfig) error {
	if b.Backend != nil {
		return b.Backend.Setup(ctx, config)
	}
	return nil
}

// Initialize delegates to the embedded Backend
func (b *StreamingBackend) Initialize(ctx context.Context) error {
	if b.Backend != nil {
		return b.Backend.Initialize(ctx)
	}
	return nil
}

// Config delegates to the embedded Backend
func (b *StreamingBackend) Config() map[string]any {
	if b.Backend != nil {
		return b.Backend.Config()
	}
	return nil
}

// Type delegates to the embedded Backend
func (b *StreamingBackend) Type() string {
	if b.Backend != nil {
		return b.Backend.Type()
	}
	return ""
}

// Class delegates to the embedded Backend
func (b *StreamingBackend) Class() logical.BackendClass {
	if b.Backend != nil {
		return b.Backend.Class()
	}
	return logical.ClassUnknown
}

// ExtractToken delegates to the embedded Backend
func (b *StreamingBackend) ExtractToken(r *http.Request) string {
	if b.Backend != nil {
		return b.Backend.ExtractToken(r)
	}
	return ""
}

// TransparentModeProvider interface implementation

// IsTransparentMode returns whether transparent mode is enabled for this backend
func (b *StreamingBackend) IsTransparentMode() bool {
	return b.TransparentConfig != nil && b.TransparentConfig.Enabled
}

// GetAutoAuthPath returns the auth mount path for implicit authentication
func (b *StreamingBackend) GetAutoAuthPath() string {
	if b.TransparentConfig == nil {
		return ""
	}
	return b.TransparentConfig.AutoAuthPath
}

// GetTransparentRole extracts the role name from the request path
func (b *StreamingBackend) GetTransparentRole(path string) string {
	if b.TransparentConfig == nil {
		return ""
	}

	// Use custom pattern or default
	pattern := b.TransparentConfig.RolePattern
	if pattern == nil {
		pattern = DefaultTransparentRolePattern
	}

	matches := pattern.FindStringSubmatch(path)
	if len(matches) > 1 {
		return matches[1] // First capture group is the role
	}
	return b.TransparentConfig.DefaultRole
}

// RewriteTransparentPath rewrites a transparent path to standard path
func (b *StreamingBackend) RewriteTransparentPath(path string) string {
	if b.TransparentConfig == nil {
		return path
	}

	rewriter := b.TransparentConfig.PathRewriter
	if rewriter == nil {
		rewriter = DefaultPathRewriter
	}
	return rewriter(path)
}

// SetTransparentConfig updates the transparent mode configuration at runtime
func (b *StreamingBackend) SetTransparentConfig(config *TransparentConfig) {
	b.TransparentConfig = config
	// Reset unauthPaths so it gets re-initialized with new config
	b.unauthPathsOnce = sync.Once{}
	b.unauthPaths = nil
}

// InitProxy creates a standard reverse proxy with the given transport.
// The proxy uses an empty Director (providers prepare requests before ServeHTTP)
// and a standard error handler that logs and returns 502.
// Logger must be set on the StreamingBackend before calling this method.
func (b *StreamingBackend) InitProxy(transport http.RoundTripper) {
	b.Proxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			b.Logger.Error("proxy error",
				logger.Err(err),
				logger.String("target_url", r.URL.String()),
			)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
}

// initUnauthPaths parses UnauthenticatedPaths into radix tree + wildcard slice
func (b *StreamingBackend) initUnauthPaths() {
	if len(b.UnauthenticatedPaths) == 0 {
		b.unauthPaths = &unauthPathsEntry{
			paths: radix.New(),
		}
		return
	}

	tree := radix.New()
	var wildcards []wildcardPath

	for _, path := range b.UnauthenticatedPaths {
		if strings.Contains(path, "+") {
			// Paths with wildcards stored separately
			isPrefix := strings.HasSuffix(path, "*")
			if isPrefix {
				path = path[:len(path)-1]
			}
			wildcards = append(wildcards, wildcardPath{
				segments: strings.Split(path, "/"),
				isPrefix: isPrefix,
			})
		} else {
			// Paths without wildcards go in radix tree
			// Value indicates if it's a prefix match
			isPrefix := strings.HasSuffix(path, "*")
			if isPrefix {
				path = path[:len(path)-1]
			}
			tree.Insert(path, isPrefix)
		}
	}

	b.unauthPaths = &unauthPathsEntry{
		paths:         tree,
		wildcardPaths: wildcards,
	}
}

// IsUnauthenticatedPath checks if the path matches an unauthenticated pattern.
// Uses radix tree for O(log n) lookup with wildcard fallback.
func (b *StreamingBackend) IsUnauthenticatedPath(path string) bool {
	b.unauthPathsOnce.Do(b.initUnauthPaths)

	if b.unauthPaths == nil {
		return false
	}

	// Normalize path: remove role/X/gateway prefix to get the actual Vault path
	// Input: "role/provisionner/gateway/v1/pki/issuer/abc/pem"
	// Output: "v1/pki/issuer/abc/pem"
	if idx := strings.Index(path, "/gateway/"); idx >= 0 {
		path = path[idx+9:] // len("/gateway/") = 9
	} else {
		path = strings.TrimPrefix(path, "gateway/")
		path = strings.TrimPrefix(path, "gateway")
	}
	path = strings.TrimPrefix(path, "/")

	// Check radix tree (exact and prefix matches)
	match, raw, ok := b.unauthPaths.paths.LongestPrefix(path)
	if ok {
		isPrefix := raw.(bool)
		if isPrefix {
			return strings.HasPrefix(path, match)
		}
		if match == path {
			return true
		}
	}

	// Check wildcard patterns
	pathParts := strings.Split(path, "/")
	for _, w := range b.unauthPaths.wildcardPaths {
		if matchWildcardSegments(pathParts, w.segments, w.isPrefix) {
			return true
		}
	}

	return false
}

// matchWildcardSegments checks if path segments match a wildcard pattern
func matchWildcardSegments(pathParts, patternParts []string, isPrefix bool) bool {
	if !isPrefix && len(pathParts) != len(patternParts) {
		return false
	}
	if isPrefix && len(pathParts) < len(patternParts) {
		return false
	}

	for i, patternPart := range patternParts {
		if patternPart == "+" {
			continue // + matches any single segment
		}
		if pathParts[i] != patternPart {
			return false
		}
	}
	return true
}
