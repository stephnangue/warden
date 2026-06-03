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
	"sync/atomic"
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

// DefaultAuthRolePattern is the default pattern for extracting the auth role from transparent paths.
// Matches: role/{role}/gateway... and extracts the auth role name.
var DefaultAuthRolePattern = regexp.MustCompile(`^role/([^/]+)/gateway`)

// DefaultPathRewriter rewrites transparent paths to standard paths.
// Converts: role/X/gateway/... -> gateway/...
func DefaultPathRewriter(path string) string {
	return DefaultAuthRolePattern.ReplaceAllString(path, "gateway")
}

// TransparentConfig holds the authentication configuration for implicit auth.
// When set on a StreamingBackend, the provider performs implicit JWT or cert
// authentication on every request — no explicit login step is needed.
type TransparentConfig struct {
	// AutoAuthPath is the auth mount path for implicit authentication (e.g., "auth/jwt/")
	AutoAuthPath string

	// DefaultAuthRole is the auth role to use when not specified in URL path
	DefaultAuthRole string

	// AuthRolePattern is the regex pattern to extract the auth role from path (optional)
	// If nil, uses DefaultAuthRolePattern: `^role/([^/]+)/gateway`
	// First capture group is used as the auth role name
	AuthRolePattern *regexp.Regexp

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

// swappableTransport wraps an http.RoundTripper whose underlying transport
// can be replaced atomically at runtime. ReverseProxy and custom backends
// hold a pointer to one instance and never need to re-read Transport; the
// swappable always dispatches to the current underlying transport.
//
// Uses atomic.Pointer[http.RoundTripper] (pointer to interface) rather than
// atomic.Value because Store requires every value to have the same concrete
// type — providers may swap an *http.Transport for an *rewritingTransport
// from a test, which atomic.Value rejects with a panic.
type swappableTransport struct {
	cur atomic.Pointer[http.RoundTripper]
}

func newSwappableTransport(initial http.RoundTripper) *swappableTransport {
	s := &swappableTransport{}
	if initial != nil {
		s.cur.Store(&initial)
	}
	return s
}

func (s *swappableTransport) load() http.RoundTripper {
	p := s.cur.Load()
	if p == nil {
		return nil
	}
	return *p
}

func (s *swappableTransport) store(t http.RoundTripper) {
	s.cur.Store(&t)
}

// RoundTrip satisfies http.RoundTripper by dispatching to the current
// underlying transport. Falls back to http.DefaultTransport when nothing has
// been installed yet so callers don't have to nil-check.
func (s *swappableTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t := s.load()
	if t == nil {
		t = http.DefaultTransport
	}
	return t.RoundTrip(r)
}

// StreamingBackend implements logical.Backend for streaming/proxy operations.
// It combines streaming paths (for proxy operations) with regular framework paths
// (for configuration and management).
//
// Mutable runtime fields (MaxBodySize, Timeout, TransparentConfig, transport)
// are held in atomic backing storage and exposed via accessor methods. Direct
// struct-field writes to the legacy names are no longer possible (the fields
// are unexported); use MaxBodySize() / SetMaxBodySize(), Timeout() / SetTimeout(),
// TransparentConfig() / SetTransparentConfig(), Transport() / SetTransport().
// This makes hot-path reads race-detector clean against concurrent config
// writes without each provider having to coordinate its own RWMutex.
type StreamingBackend struct {
	// StreamingPaths are paths that handle streaming operations (e.g., gateway/*)
	StreamingPaths []*StreamingPath

	// UnauthenticatedPaths are paths that can be accessed without authentication.
	// These are hardcoded by the provider for read-only endpoints that some clients
	// access without sending tokens (e.g., PKI certificate PEM files).
	// Supports: exact match, prefix match (*), segment wildcard (+)
	UnauthenticatedPaths []string

	// ParseStreamBody enables request body parsing for streaming requests.
	// When true, the core parses application/json and application/x-www-form-urlencoded
	// bodies into req.Data before policy evaluation, then restores the body so
	// the streaming handler can still read it.
	// Default: false (body is passed raw to the streaming handler).
	ParseStreamBody bool

	// Backend is the embedded standard framework backend for non-streaming paths
	*Backend

	// Proxy is the shared reverse proxy for streaming requests.
	// Initialized via InitProxy with a provider-specific transport. Proxy.Transport
	// is set to the swappable transport, so subsequent SetTransport calls update
	// both this Proxy and any custom-backend handler that reads via Transport().
	Proxy *httputil.ReverseProxy

	// Logger is the provider's scoped logger (set via conf.Logger.WithSubsystem).
	Logger *logger.GatedLogger

	// StorageView is the provider's storage backend for persisting configuration.
	StorageView sdklogical.Storage

	// Atomic backing storage for runtime-mutable fields. Read/write only via
	// the typed accessor methods below.
	maxBodySize       atomic.Int64
	timeout           atomic.Int64 // nanoseconds
	transparentConfig atomic.Pointer[TransparentConfig]
	// transport is lazily-initialized via transportOnce so concurrent first
	// SetTransport / Transport / InitProxy calls don't race on the pointer-
	// field assignment. The same swappable lives for the lifetime of the
	// backend; SetTransport mutates its underlying.
	transport     *swappableTransport
	transportOnce sync.Once

	// Internal state
	streamingPathsRe []*regexp.Regexp
	streamingOnce    sync.Once

	// unauthPaths holds the parsed unauthenticated paths (radix tree + wildcards).
	// unauthMu serializes the reset performed by SetTransparentConfig and the
	// once-only init performed by initUnauthPaths so concurrent config writes
	// can't race on the sync.Once or the pointer.
	// unauthPathsOnce is a *sync.Once (not a value) so the reset in
	// SetTransparentConfig replaces the pointer rather than copying a value —
	// avoids go vet's -copylocks complaint about reassigning a sync.Once
	// after first use.
	unauthMu        sync.Mutex
	unauthPaths     *unauthPathsEntry
	unauthPathsOnce *sync.Once
}

// MaxBodySize returns the maximum request body size in bytes.
func (b *StreamingBackend) MaxBodySize() int64 { return b.maxBodySize.Load() }

// SetMaxBodySize atomically updates the maximum request body size.
func (b *StreamingBackend) SetMaxBodySize(v int64) { b.maxBodySize.Store(v) }

// Timeout returns the request timeout duration.
func (b *StreamingBackend) Timeout() time.Duration { return time.Duration(b.timeout.Load()) }

// SetTimeout atomically updates the request timeout duration.
func (b *StreamingBackend) SetTimeout(d time.Duration) { b.timeout.Store(int64(d)) }

// emptyTransparentConfig is returned by TransparentConfig() when no config
// has been installed. Sharing a single pointer avoids per-call allocation
// on the (rare) cold path; callers must treat the returned value as read-only.
var emptyTransparentConfig = &TransparentConfig{}

// TransparentConfig returns the current implicit-auth configuration. Never
// returns nil — when nothing has been installed yet (a freshly-constructed
// StreamingBackend that hasn't been seeded), returns a shared empty
// TransparentConfig so callers can safely chain field accesses. Use
// IsTransparentMode() to distinguish "not configured" from "configured
// with empty fields".
func (b *StreamingBackend) TransparentConfig() *TransparentConfig {
	if tc := b.transparentConfig.Load(); tc != nil {
		return tc
	}
	return emptyTransparentConfig
}

// ensureTransport lazily initializes the swappable wrapper. Idempotent and
// concurrency-safe via transportOnce. Callers must use this before reading
// or writing b.transport.
func (b *StreamingBackend) ensureTransport() *swappableTransport {
	b.transportOnce.Do(func() {
		b.transport = newSwappableTransport(nil)
	})
	return b.transport
}

// Transport returns the framework's swappable transport wrapper. The wrapper
// itself stays stable for the lifetime of the backend; the underlying
// http.RoundTripper changes when SetTransport / InitProxy install one. Before
// any transport is installed, RoundTrip on the wrapper falls back to
// http.DefaultTransport.
func (b *StreamingBackend) Transport() http.RoundTripper {
	return b.ensureTransport()
}

// SetTransport atomically replaces the upstream transport. The same swappable
// dispatches for Proxy.Transport and for custom backends reading via Transport(),
// so a single SetTransport call updates every hot-path reader.
func (b *StreamingBackend) SetTransport(t http.RoundTripper) {
	b.ensureTransport().store(t)
}

// Ensure StreamingBackend implements logical.Backend and logical.StreamBodyParser
var _ logical.Backend = (*StreamingBackend)(nil)
var _ logical.StreamBodyParser = (*StreamingBackend)(nil)

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

// IsTransparentMode returns whether the backend has an auth config set
func (b *StreamingBackend) IsTransparentMode() bool {
	return b.transparentConfig.Load() != nil
}

// GetAutoAuthPath returns the auth mount path for implicit authentication
func (b *StreamingBackend) GetAutoAuthPath() string {
	tc := b.transparentConfig.Load()
	if tc == nil {
		return ""
	}
	return tc.AutoAuthPath
}

// GetAuthRole extracts the auth role name from the request path. Returns
// "" when the path does not encode a role; the mount-level default_role
// is returned separately by GetDefaultAuthRole.
func (b *StreamingBackend) GetAuthRole(path string, _ *logical.Request) string {
	tc := b.transparentConfig.Load()
	if tc == nil {
		return ""
	}

	pattern := tc.AuthRolePattern
	if pattern == nil {
		pattern = DefaultAuthRolePattern
	}

	matches := pattern.FindStringSubmatch(path)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// GetDefaultAuthRole returns the mount-level default_role config value.
func (b *StreamingBackend) GetDefaultAuthRole() string {
	tc := b.transparentConfig.Load()
	if tc == nil {
		return ""
	}
	return tc.DefaultAuthRole
}

// RewriteTransparentPath rewrites a transparent path to standard path
func (b *StreamingBackend) RewriteTransparentPath(path string) string {
	tc := b.transparentConfig.Load()
	if tc == nil {
		return path
	}

	rewriter := tc.PathRewriter
	if rewriter == nil {
		rewriter = DefaultPathRewriter
	}
	return rewriter(path)
}

// SetTransparentConfig updates the implicit auth configuration at runtime.
// The new pointer is installed atomically; readers via GetAutoAuthPath etc
// observe either the old or new config, never a torn value.
func (b *StreamingBackend) SetTransparentConfig(config *TransparentConfig) {
	b.transparentConfig.Store(config)
	// Reset unauthPaths so it gets re-initialized with new config. Guarded
	// by unauthMu against concurrent SetTransparentConfig + initUnauthPaths.
	b.unauthMu.Lock()
	b.unauthPathsOnce = &sync.Once{}
	b.unauthPaths = nil
	b.unauthMu.Unlock()
}

// InitProxy creates a standard reverse proxy backed by the framework's
// swappable transport. After this call:
//   - b.Proxy.Transport is the swappable wrapper, so subsequent SetTransport
//     calls update both this Proxy and any custom-backend handler that reads
//     via Transport() — no per-provider transport re-assignment needed.
//   - Transport() returns the same swappable, with the initial transport
//     installed atomically.
//
// The proxy uses an empty Director (providers prepare requests before ServeHTTP)
// and a standard error handler that logs and returns 502.
// Logger must be set on the StreamingBackend before calling this method.
func (b *StreamingBackend) InitProxy(transport http.RoundTripper) {
	swap := b.ensureTransport()
	swap.store(transport)
	b.Proxy = &httputil.ReverseProxy{
		Director:  func(req *http.Request) {},
		Transport: swap,
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

// IsTransparentPath checks if the given path should trigger transparent authentication.
// For streaming backends, this matches gateway paths: "gateway", "gateway/...",
// "role/X/gateway", "role/X/gateway/...".
func (b *StreamingBackend) IsTransparentPath(path string) bool {
	return strings.HasPrefix(path, "gateway") || strings.Contains(path, "/gateway")
}

// IsUnauthenticatedPath checks if the path matches an unauthenticated pattern.
// Uses radix tree for O(log n) lookup with wildcard fallback. Subtypes may
// override to inspect the request.
func (b *StreamingBackend) IsUnauthenticatedPath(_ *http.Request, path string) bool {
	// Both the Once.Do init and the SetTransparentConfig reset serialize
	// through unauthMu so neither tears the once+pointer pair.
	b.unauthMu.Lock()
	if b.unauthPathsOnce == nil {
		b.unauthPathsOnce = &sync.Once{}
	}
	b.unauthPathsOnce.Do(b.initUnauthPaths)
	paths := b.unauthPaths
	b.unauthMu.Unlock()

	if paths == nil {
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
	match, raw, ok := paths.paths.LongestPrefix(path)
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
	for _, w := range paths.wildcardPaths {
		if matchWildcardSegments(pathParts, w.segments, w.isPrefix) {
			return true
		}
	}

	return false
}

// ShouldParseStreamBody implements logical.StreamBodyParser. Subtypes may
// override to inspect the request.
func (b *StreamingBackend) ShouldParseStreamBody(_ *http.Request) bool {
	return b.ParseStreamBody
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
