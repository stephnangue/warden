// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Customized for warden to support streaming/proxy backends

package framework

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logical"
)

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

	// Backend is the embedded standard framework backend for non-streaming paths
	*Backend

	// Internal state
	streamingPathsRe []*regexp.Regexp
	streamingOnce    sync.Once
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
	return path.Handler(ctx, req, fd)
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
		// e.g., "gateway/.*" -> "gateway/*"
		pattern := sp.Pattern
		if strings.HasSuffix(pattern, ".*") {
			pattern = strings.TrimSuffix(pattern, ".*") + "*"
		}
		// Remove regex anchors if present
		pattern = strings.TrimPrefix(pattern, "^")
		pattern = strings.TrimSuffix(pattern, "$")
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
