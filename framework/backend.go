// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Copied from github.com/openbao/openbao/sdk/v2/framework and customized for warden

package framework

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// regexSingletonCache is used to reduce memory usage for multiple backends
// using similar patterns.
var regexSingletonCache sync.Map

// Backend is an implementation of logical.Backend that allows
// the implementer to code a backend using a programmer-friendly framework.
type Backend struct {
	// Help is the help text shown when a help request is made on the root.
	Help string

	// Paths are the various routes that the backend responds to.
	Paths []*Path

	// PathsSpecial is the list of path patterns that require special privileges.
	PathsSpecial *logical.Paths

	// InitializeFunc is the callback invoked after a plugin has been mounted.
	InitializeFunc InitializeFunc

	// Clean is called on unload to clean up connections or file handles.
	Clean CleanupFunc

	// BackendClass is the warden-specific backend class (Provider, Auth, System)
	BackendClass logical.BackendClass

	// BackendType is a string identifier for the backend type (e.g., "jwt", "aws")
	BackendType string

	// TokenExtractor is the warden-specific token extraction function
	TokenExtractor func(r *http.Request) string

	// config stores the backend configuration
	config map[string]any
	once    sync.Once
	pathsRe []*regexp.Regexp
	logger logger.GatedLogger
}

// Ensure Backend implements logical.Backend
var _ logical.Backend = (*Backend)(nil)


// OperationFunc is the callback called for an operation on a path.
type OperationFunc func(context.Context, *logical.Request, *FieldData) (*logical.Response, error)

// ExistenceFunc is the callback called for an existence check on a path.
type ExistenceFunc func(context.Context, *logical.Request, *FieldData) (bool, error)

// CleanupFunc is the callback for backend unload.
type CleanupFunc func(context.Context)

// InitializeFunc is the callback invoked after a backend has been mounted.
type InitializeFunc func(context.Context) error

// Initialize is the logical.Backend implementation.
func (b *Backend) Initialize(ctx context.Context) error {
	if b.InitializeFunc != nil {
		return b.InitializeFunc(ctx)
	}
	return nil
}

// HandleExistenceCheck is the logical.Backend implementation.
func (b *Backend) HandleExistenceCheck(ctx context.Context, req *logical.Request) (checkFound bool, exists bool, err error) {
	b.once.Do(b.init)

	switch req.Operation {
	case logical.CreateOperation:
	case logical.UpdateOperation:
	default:
		return false, false, fmt.Errorf("incorrect operation type %v for an existence check", req.Operation)
	}

	path, captures := b.route(req.Path)
	if path == nil {
		return false, false, sdklogical.ErrUnsupportedPath
	}

	if path.ExistenceCheck == nil {
		return false, false, nil
	}

	checkFound = true

	raw := make(map[string]interface{}, len(path.Fields))
	for k, v := range req.Data {
		raw[k] = v
	}
	for k, v := range captures {
		raw[k] = v
	}

	fd := FieldData{
		Raw:    raw,
		Schema: path.Fields,
	}

	err = fd.Validate()
	if err != nil {
		return false, false, errutil.UserError{Err: err.Error()}
	}

	exists, err = path.ExistenceCheck(ctx, req, &fd)
	return checkFound, exists, err
}

// HandleRequest is the logical.Backend implementation.
func (b *Backend) HandleRequest(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	b.once.Do(b.init)

	// If the path is empty and it is a help operation, handle that.
	if req.Path == "" && req.Operation == logical.HelpOperation {
		return b.handleRootHelp(req)
	}

	// Find the matching route
	path, captures := b.route(req.Path)
	if path == nil {
		return nil, sdklogical.ErrUnsupportedPath
	}

	// Build up the data for the route
	raw := make(map[string]interface{}, len(path.Fields))
	var ignored []string
	for k, v := range req.Data {
		raw[k] = v
		if !path.TakesArbitraryInput && path.Fields[k] == nil {
			ignored = append(ignored, k)
		}
	}

	var replaced []string
	for k, v := range captures {
		if raw[k] != nil {
			replaced = append(replaced, k)
		}
		raw[k] = v
	}

	// Look up the callback for this operation
	var callback OperationFunc

	if path.Operations != nil {
		if op, ok := path.Operations[req.Operation]; ok {
			callback = op.Handler()
		}
	} else {
		callback = path.Callbacks[req.Operation]
	}
	ok := callback != nil

	if !ok {
		if req.Operation == logical.HelpOperation {
			callback = path.helpCallback(b)
			ok = true
		}
	}
	if !ok {
		return nil, sdklogical.ErrUnsupportedOperation
	}

	fd := FieldData{
		Raw:    raw,
		Schema: path.Fields,
	}

	if req.Operation != logical.HelpOperation {
		err := fd.Validate()
		if err != nil {
			return logical.ErrorResponse(logical.ErrBadRequestf("field validation failed: %s", err.Error())), nil
		}
	}

	resp, err := callback(ctx, req, &fd)
	if err != nil {
		return resp, err
	}

	switch resp {
	case nil:
	default:
		sort.Strings(ignored)
		if len(ignored) != 0 {
			resp.AddWarning(fmt.Sprintf("Endpoint ignored these unrecognized parameters: %v", ignored))
		}
		if len(replaced) != 0 {
			resp.AddWarning(fmt.Sprintf("Endpoint replaced the value of these parameters with the values captured from the endpoint's path: %v", replaced))
		}
	}

	return resp, nil
}

// SpecialPaths is the logical.Backend implementation.
func (b *Backend) SpecialPaths() *logical.Paths {
	return b.PathsSpecial
}

// Cleanup is used to release resources and prepare to stop the backend
func (b *Backend) Cleanup(ctx context.Context) {
	if b.Clean != nil {
		b.Clean(ctx)
	}
}

// Setup is used to initialize the backend with the initial backend configuration
func (b *Backend) Setup(ctx context.Context, config *logical.BackendConfig) error {
	b.config = config.Config
	b.logger = *config.Logger
	return nil
}


// Config returns the backend configuration
func (b *Backend) Config() map[string]any {
	return b.config
}

// Type returns the backend type string
func (b *Backend) Type() string {
	return b.BackendType
}

// Class returns the warden backend class
func (b *Backend) Class() logical.BackendClass {
	return b.BackendClass
}

// ExtractToken extracts token from HTTP request using the configured extractor.
// If no custom extractor is set, uses the default extraction logic:
// 1. X-Warden-Token header
// 2. Authorization: Bearer <token>
func (b *Backend) ExtractToken(r *http.Request) string {
	if b.TokenExtractor != nil {
		return b.TokenExtractor(r)
	}
	return DefaultTokenExtractor(r)
}

// DefaultTokenExtractor is the default token extraction function.
// It checks X-Warden-Token header first, then falls back to Authorization: Bearer.
func DefaultTokenExtractor(r *http.Request) string {
	// Try X-Warden-Token header first
	if token := r.Header.Get("X-Warden-Token"); token != "" {
		return token
	}
	// Fall back to Authorization: Bearer
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
		return authHeader[7:]
	}
	return ""
}

// Route looks up the path that would be used for a given path string.
func (b *Backend) Route(path string) *Path {
	result, _ := b.route(path)
	return result
}

func (b *Backend) init() {
	b.pathsRe = make([]*regexp.Regexp, len(b.Paths))
	for i, p := range b.Paths {
		if len(p.Pattern) == 0 {
			panic("Routing pattern cannot be blank")
		}
		// Automatically anchor the pattern
		if p.Pattern[0] != '^' {
			p.Pattern = "^" + p.Pattern
		}
		if p.Pattern[len(p.Pattern)-1] != '$' {
			p.Pattern = p.Pattern + "$"
		}
		regexRaw, ok := regexSingletonCache.Load(p.Pattern)
		if !ok {
			regexRaw = regexp.MustCompile(p.Pattern)
			regexSingletonCache.Store(p.Pattern, regexRaw)
		}
		b.pathsRe[i] = regexRaw.(*regexp.Regexp)
	}
}

func (b *Backend) route(path string) (*Path, map[string]string) {
	b.once.Do(b.init)

	for i, re := range b.pathsRe {
		matches := re.FindStringSubmatch(path)
		if matches == nil {
			continue
		}

		var captures map[string]string
		path := b.Paths[i]
		if captureNames := re.SubexpNames(); len(captureNames) > 1 {
			captures = make(map[string]string, len(captureNames))
			for i, name := range captureNames {
				if name != "" {
					captures[name] = matches[i]
				}
			}
		}

		return path, captures
	}

	return nil, nil
}

func (b *Backend) handleRootHelp(req *logical.Request) (*logical.Response, error) {
	pathsMap := make(map[string]*Path)
	paths := make([]string, 0, len(b.Paths))
	for i, p := range b.pathsRe {
		paths = append(paths, p.String())
		pathsMap[p.String()] = b.Paths[i]
	}
	sort.Strings(paths)

	pathData := make([]rootHelpTemplatePath, 0, len(paths))
	for _, route := range paths {
		p := pathsMap[route]
		pathData = append(pathData, rootHelpTemplatePath{
			Path: route,
			Help: strings.TrimSpace(p.HelpSynopsis),
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

type rootHelpTemplateData struct {
	Help  string
	Paths []rootHelpTemplatePath
}

type rootHelpTemplatePath struct {
	Path string
	Help string
}

const rootHelpTemplate = `
## DESCRIPTION

{{.Help}}

## PATHS

The following paths are supported by this backend. To view help for
any of the paths below, use the help command with any route matching
the path pattern.

{{range .Paths}}{{indent 4 .Path}}
{{indent 8 .Help}}

{{end}}
`
