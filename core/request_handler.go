package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-multierror"
	"github.com/openbao/openbao/sdk/v2/helper/pathmanager"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	authhelper "github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/credential/drivers"
	"github.com/stephnangue/warden/helper"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

const (
	// maxRequestBodySize is the maximum allowed size for JSON request bodies on sys/ API paths.
	// This prevents unbounded memory allocation from malicious large payloads.
	maxRequestBodySize = 32 << 20 // 32MB
)

var (
	// restrictedSysAPIs is the set of `sys/` APIs available only in the root namespace.
	restrictedSysAPIs = pathmanager.New()
)

func init() {
	restrictedSysAPIs.AddPaths([]string{
		"audit-hash",
		"audit",
		"config/auditing",
		"config/cors",
		"config/reload",
		"config/state",
		"config/ui",
		"decode-token",
		"generate-recovery-token",
		"generate-root",
		"health",
		"host-info",
		"in-flight-req",
		"init",
		"internal/counters/activity",
		"internal/counters/activity/export",
		"internal/counters/activity/monthly",
		"internal/counters/config",
		"internal/inspect/router",
		"key-status",
		"loggers",
		"managed-keys",
		"metrics",
		"mfa/method",
		"monitor",
		"pprof",
		"quotas/config",
		"quotas/lease-count",
		"quotas/rate-limit",
		"raw",
		"rekey-recovery-key",
		"rekey",
		"replication/merkle-check",
		"replication/recover",
		"replication/reindex",
		"replication/status",
		"rotate",
		"rotate/root",
		"rotate/config",
		"rotate/keyring",
		"rotate/keyring/config",
		"seal",
		"sealwrap/rewrap",
		"step-down",
		"storage",
		"sync/config",
		"unseal",
	})
}

func (c *Core) CheckToken(ctx context.Context, req *logical.Request, unauth bool) (*logical.Auth, *CBP, *logical.TokenEntry, error) {
	var cbp *CBP
	var te *logical.TokenEntry

	// Even if unauth, if a token is provided, there's little reason not to
	// gather as much info as possible for the audit log
	if !unauth || (unauth && req.ClientToken != "") {
		var err error
		cbp, te, err = c.fetchCBPAndTokenEntry(ctx, req)
		// In the unauth case we don't want to fail the command, since it's
		// unauth, we just have no information to attach to the request, so
		// ignore errors...this was best-effort anyways
		if err != nil && !unauth {
			if c.standby.Load() || (c.activeContext != nil && c.activeContext.Err() != nil) {
				return nil, cbp, te, ErrStandby
			}
			return nil, cbp, te, err
		}
	}

	// For create/update operations, perform existence check to determine the actual operation
	if req.Operation == logical.CreateOperation || req.Operation == logical.UpdateOperation {
		existsResp, checkExists, resourceExists, err := c.router.RouteExistenceCheck(ctx, req)
		switch err {
		case sdklogical.ErrUnsupportedPath:
			// Backend doesn't support existence check, continue with original operation
			checkExists = false
		case nil:
			if existsResp != nil && existsResp.IsError() {
				return nil, cbp, te, existsResp.Error()
			}
		default:
			c.logger.Error("failed to run existence check", logger.Err(err))
			return nil, cbp, te, ErrInternalError
		}

		// Adjust operation based on existence check result
		if checkExists {
			if resourceExists {
				// Resource exists, this should be an update
				req.Operation = logical.UpdateOperation
			} else {
				// Resource doesn't exist, this should be a create
				req.Operation = logical.CreateOperation
			}
		}
	}

	// Check if this is a root protected path
	rootPath := c.router.RootPath(ctx, req.Path)
	if rootPath && unauth {
		return nil, nil, nil, errors.New("cannot access root path in unauthenticated request")
	}

	// Create the auth response
	auth := &logical.Auth{
		ClientToken:   req.ClientToken,
		TokenAccessor: req.ClientTokenAccessor,
	}

	if te != nil {
		auth.Policies = te.Policies
		auth.TokenType = te.Type
	}

	// Check the standard non-root CBPs. Return the token entry if it's not
	// allowed so we can decrement the use count (to be implemented in the future)
	accessControlResults := c.performPolicyChecks(ctx, cbp, te, req, &PolicyCheckOpts{
		Unauth:            unauth,
		RootPrivsRequired: rootPath,
	})

	auth.PolicyResults = &sdklogical.PolicyResults{
		Allowed: accessControlResults.Allowed,
	}
	// Carry the MCP decision (when an mcp { } rule-set was consulted)
	// through to buildAuditAuth — that's where it gets surfaced in the
	// audit record — and to the deny-response path below for the
	// typed-error wrap.
	if accessControlResults.CBPResults != nil && accessControlResults.CBPResults.MCPDecision != nil {
		auth.MCPDecision = accessControlResults.CBPResults.MCPDecision
	}
	// Carry the path-level CEL condition decision through to buildAuditAuth.
	if accessControlResults.CBPResults != nil && accessControlResults.CBPResults.Condition != nil {
		auth.Condition = accessControlResults.CBPResults.Condition
	}

	if !accessControlResults.Allowed {
		retErr := accessControlResults.Error

		if accessControlResults.Error.ErrorOrNil() == nil || accessControlResults.DeniedError {
			// Wrap the permission-denied error with the MCP decision
			// when the denial came from an mcp { } gate, so the HTTP
			// layer can render the OAuth-shaped 403 body. Unwrap()
			// returns ErrPermissionDenied so every existing
			// errors.Is(err, ErrPermissionDenied) call site keeps
			// working unchanged.
			if auth.MCPDecision != nil && auth.MCPDecision.Decision == "deny" {
				retErr = multierror.Append(retErr, &ErrMCPPolicyDenied{Decision: auth.MCPDecision})
			} else {
				retErr = multierror.Append(retErr, sdklogical.ErrPermissionDenied)
			}
		}
		return auth, cbp, te, retErr
	}

	if accessControlResults.CBPResults != nil && len(accessControlResults.CBPResults.GrantingPolicies) > 0 {
		auth.PolicyResults.GrantingPolicies = accessControlResults.CBPResults.GrantingPolicies
	}

	return auth, cbp, te, nil
}

func (c *Core) fetchCBPAndTokenEntry(ctx context.Context, req *logical.Request) (*CBP, *logical.TokenEntry, error) {
	// Ensure there is a client token
	if req.ClientToken == "" {
		return nil, nil, sdklogical.ErrPermissionDenied
	}

	if c.tokenStore == nil && req.TokenEntry() == nil {
		c.logger.Error("token store is unavailable")
		return nil, nil, ErrInternalError
	}

	// Inject client IP into context so validateIPBinding can read it
	if req.ClientIP != "" {
		ctx = context.WithValue(ctx, logical.ClientIPKey, req.ClientIP)
	}

	// Resolve the token policy
	var te *logical.TokenEntry
	switch req.TokenEntry() {
	case nil:
		var err error
		te, err = c.LookupToken(ctx, req.ClientToken)
		if err != nil {
			// Authentication/authorization failures should return permission denied
			if errors.Is(err, ErrTokenNamespaceMismatch) ||
				errors.Is(err, ErrTokenNotFound) ||
				errors.Is(err, ErrTokenExpired) ||
				errors.Is(err, ErrOriginViolation) ||
				errors.Is(err, ErrTypeNotFound) {
				c.logger.Warn("token lookup failed", logger.Err(err))
				return nil, nil, sdklogical.ErrPermissionDenied
			}
			c.logger.Error("failed to lookup token", logger.Err(err))
			return nil, nil, ErrInternalError
		}
		req.SetTokenEntry(te)
	default:
		te = req.TokenEntry()
	}

	// Ensure the token is valid
	if te == nil {
		return nil, nil, sdklogical.ErrPermissionDenied
	}

	policyNames := make(map[string][]string)
	// Add tokens policies
	policyNames[te.NamespaceID] = append(policyNames[te.NamespaceID], te.Policies...)

	tokenNS, err := c.NamespaceByID(ctx, te.NamespaceID)
	if err != nil {
		c.logger.Error("failed to fetch token namespace", logger.Err(err))
		return nil, nil, ErrInternalError
	}

	if tokenNS == nil {
		c.logger.Error("failed to fetch token namespace", logger.Err(namespace.ErrNoNamespace))
		return nil, nil, ErrInternalError
	}

	tokenCtx := namespace.ContextWithNamespace(ctx, tokenNS)

	// Construct the corresponding CBP object. CBP construction should be
	// performed on the token's namespace.
	if c.policyStore == nil {
		c.logger.Error("policy store is unavailable")
		return nil, nil, ErrInternalError
	}
	cbp, err := c.policyStore.CBP(tokenCtx, policyNames)
	if err != nil {
		c.logger.Error("failed to construct CBP", logger.Err(err))
		return nil, nil, ErrInternalError
	}

	return cbp, te, nil
}

func (c *Core) HandleRequest(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	// Check if the core is sealed
	if c.Sealed() {
		return logical.ErrorResponse(logical.ErrServiceUnavailable("Warden is sealed")), nil
	}

	// Check if the core has an active context
	if c.activeContext == nil || c.activeContext.Err() != nil {
		if c.standby.Load() {
			return nil, ErrStandby
		}
		return logical.ErrorResponse(logical.ErrServiceUnavailable("server context canceled")), nil
	}

	// Extract namespace header from HTTP request
	var nsHeader string
	if req.HTTPRequest != nil {
		nsHeader = req.HTTPRequest.Header.Get("X-Warden-Namespace")
	}

	// Sanitize the request path.
	// Preserve trailing slash for help operations so mount-root help works
	// (e.g., "azure/" needs the slash to match mount key "azure/" in the router).
	requestPath := req.Path
	if req.Operation != logical.HelpOperation {
		requestPath = strings.TrimSuffix(req.Path, "/")
	}

	// Resolve namespace from header and request path
	// /v1/ns1/sys/namespaces/test1 -> ns1/ and sys/namespaces/test1
	// /v1/sys/namespaces/test1 with X-Warden-Namespace=ns1 -> ns1/ and sys/namespaces/test1
	ns, trimmedPath := c.namespaceStore.ResolveNamespaceFromRequest(nsHeader, requestPath)
	if ns == nil {
		if trimmedPath != "" {
			c.logger.Warn("namespace resolution failed",
				logger.String("trimmed_path", trimmedPath),
				logger.String("namespace_header", nsHeader),
				logger.String("request_path", req.Path))
		}
		return logical.ErrorResponse(logical.ErrNotFound("namespace not found")), nil
	}

	// Check for restricted APIs in non-root namespaces
	if ns.ID != namespace.RootNamespaceID {
		if strings.HasPrefix(trimmedPath, "sys/") &&
			restrictedSysAPIs.HasPathSegments(trimmedPath[len("sys/"):]) {
			return logical.ErrorResponse(logical.ErrBadRequest("operation unavailable in namespaces")), nil
		}
	}

	// Set the resolved path (the path relative to the namespace)
	req.Path = trimmedPath

	ctx = namespace.ContextWithNamespace(ctx, ns)
	activeCtx, cancel := context.WithCancel(c.activeContext)
	defer cancel()

	go func(activeCtx context.Context, reqCtx context.Context) {
		select {
		case <-activeCtx.Done():
		case <-reqCtx.Done():
			cancel()
		}
	}(activeCtx, ctx)

	// Header-based routing has two cases driven by which X-Warden-* headers
	// are present:
	//
	//   X-Warden-Provider present (header-routing mode):
	//     Treat the request URL as the literal upstream API path. Synthesize
	//     the canonical <provider>/role/<role>/gateway/<api> shape before
	//     mount lookup. Reject against the system backend (the header isn't
	//     a routing override for system endpoints) and against SigV4-signed
	//     requests (mutating the URL would invalidate the client signature
	//     and the failure would look like an authentication bug).
	//
	//   X-Warden-Provider absent, X-Warden-Role present:
	//     Path-routing mode where the role header overrides any role baked
	//     into the URL. Rewrite the role segment in req.Path so the
	//     streaming backend's role parser sees the same role the auth
	//     resolver chooses (see isTransparentRequest).
	//
	// In both cases HTTPRequest.URL.Path is realigned with req.Path so
	// providers that read URL.Path directly see a consistent shape.
	if req.HTTPRequest != nil {
		provider := req.HTTPRequest.Header.Get("X-Warden-Provider")
		headerRole := req.HTTPRequest.Header.Get("X-Warden-Role")

		switch {
		case provider != "":
			if strings.HasPrefix(req.Path, "sys/") {
				return logical.ErrorResponse(logical.ErrBadRequest("X-Warden-Provider is not honored on system backend paths")), nil
			}
			if isSigV4Authorization(req.HTTPRequest.Header.Get("Authorization")) {
				return logical.ErrorResponse(logical.ErrBadRequest("X-Warden-Provider is not compatible with SigV4 authentication; use the path-routed /v1/<mount>/role/<role>/gateway/<api> form instead")), nil
			}
			synthesized, err := synthesizeGatewayPath(provider, headerRole, req.Path)
			if err != nil {
				return logical.ErrorResponse(logical.ErrBadRequest(err.Error())), nil
			}
			req.Path = synthesized
			req.HTTPRequest.URL.Path = "/v1/" + synthesized
			req.HTTPRequest.URL.RawPath = ""

		case headerRole != "":
			rewritten := applyRoleHeader(req.Path, headerRole)
			if rewritten != req.Path {
				req.Path = rewritten
				req.HTTPRequest.URL.Path = "/v1/" + rewritten
				req.HTTPRequest.URL.RawPath = ""
			}
		}
	}

	// For help operations, mount-root paths (e.g., "azure") may arrive without
	// a trailing slash because path.Join in the API client strips them.
	// Use the silent MatchingMount to probe with a trailing slash first,
	// so MatchingBackend doesn't log a spurious error on the initial miss.
	if req.Operation == logical.HelpOperation && !strings.HasSuffix(req.Path, "/") {
		if c.router.MatchingMount(ctx, req.Path) == "" && c.router.MatchingMount(ctx, req.Path+"/") != "" {
			req.Path = req.Path + "/"
		}
	}
	matchingBackend := c.router.MatchingBackend(ctx, req.Path)
	if matchingBackend == nil {
		c.logger.Warn("no backend mounted at path",
			logger.String("full_req_path", req.HTTPRequest.URL.Path),
			logger.String("relative_req_path", req.Path),
			logger.String("namespace", ns.Path),
		)
		return logical.ErrorResponse(logical.ErrNotFoundf("no handler for path %q", req.Path)), nil
	}

	resp, err := c.handleCancelableRequest(ctx, req)
	req.SetTokenEntry(nil)
	return resp, err
}

// sigV4AuthorizationPrefixes enumerates the SigV4 dialects whose canonical
// request includes the URL path. If any of these appears as the Authorization
// scheme, the header-routing path mutation would invalidate the client's
// signature — so we reject the request loudly instead of letting it fail as
// a confusing 401.
var sigV4AuthorizationPrefixes = []string{
	"AWS4-HMAC-SHA256",
	"ACS3-HMAC-SHA256",
}

// isSigV4Authorization reports whether the Authorization header value looks
// like a SigV4-family signature.
func isSigV4Authorization(authz string) bool {
	for _, prefix := range sigV4AuthorizationPrefixes {
		if strings.HasPrefix(authz, prefix) {
			return true
		}
	}
	return false
}

// roleSegmentPattern matches the canonical role/<role>/gateway/ segment that
// appears between the mount prefix and the upstream API path in path-routed
// requests. Only the leftmost occurrence is rewritten by applyRoleHeader.
var roleSegmentPattern = regexp.MustCompile(`role/[^/]+/gateway/`)

// applyRoleHeader rewrites the leftmost role/<role>/gateway/ segment in the
// path to match the given role. Idempotent for paths that don't carry such a
// segment (returned unchanged). Mount prefixes cannot contain a "role" or
// "gateway" segment (rejected at mount-create time), so the leftmost match
// is guaranteed to be the gateway-role segment, not part of the upstream API
// path.
func applyRoleHeader(path, role string) string {
	if role == "" {
		return path
	}
	loc := roleSegmentPattern.FindStringIndex(path)
	if loc == nil {
		return path
	}
	return path[:loc[0]] + "role/" + role + "/gateway/" + path[loc[1]:]
}

// synthesizeGatewayPath builds the canonical gateway path from a provider
// mount value and optional role. The result matches the shape the router
// and streaming backend expect:
//
//	role present: <provider>/role/<role>/gateway/<api>
//	role empty:   <provider>/gateway/<api>
//
// One leading and one trailing slash on the provider value are tolerated
// and stripped. Empty path segments and bare ".." segments are rejected.
// Whether the resolved mount exists is the caller's concern (the router's
// existing 404 path handles that).
func synthesizeGatewayPath(provider, role, apiPath string) (string, error) {
	provider = strings.TrimSuffix(provider, "/")
	provider = strings.TrimPrefix(provider, "/")
	if provider == "" {
		return "", fmt.Errorf("X-Warden-Provider value is empty")
	}
	for _, seg := range strings.Split(provider, "/") {
		if seg == "" {
			return "", fmt.Errorf("X-Warden-Provider value contains an empty path segment")
		}
		if seg == ".." {
			return "", fmt.Errorf("X-Warden-Provider value contains a path-traversal segment")
		}
	}

	apiPath = strings.TrimPrefix(apiPath, "/")

	var b strings.Builder
	b.WriteString(provider)
	b.WriteString("/")
	if role != "" {
		b.WriteString("role/")
		b.WriteString(role)
		b.WriteString("/")
	}
	b.WriteString("gateway/")
	b.WriteString(apiPath)
	return b.String(), nil
}

// statusClientClosedRequest is nginx's non-standard 499 "Client Closed
// Request": the client disconnected before any response was written. It has no
// net/http constant.
const statusClientClosedRequest = 499

// streamedStatusCode resolves the status code to record for a streamed
// response. It returns the code the writer actually captured; when nothing was
// ever written to the client (captured == 0), it derives a code from why the
// stream ended so the audit distinguishes an aborted stream from an unknown
// outcome: a canceled context (client hung up) → 499, a deadline (upstream
// timeout) → 504. If nothing was written and there is no context error, the
// outcome is genuinely unknown and 0 is preserved.
func streamedStatusCode(captured int, ctxErr error) int {
	if captured != 0 {
		return captured
	}
	switch {
	case errors.Is(ctxErr, context.Canceled):
		return statusClientClosedRequest
	case errors.Is(ctxErr, context.DeadlineExceeded):
		return http.StatusGatewayTimeout
	}
	return captured
}

func (c *Core) handleCancelableRequest(ctx context.Context, req *logical.Request) (resp *logical.Response, err error) {
	// MountPoint will not always be set at this point, so we ensure the req contains it
	req.MountPoint = c.router.MatchingMount(ctx, req.Path)

	err = c.PopulateTokenEntry(ctx, req)
	if err != nil {
		return nil, err
	}

	var auth *logical.Auth
	var te *logical.TokenEntry

	if c.isLoginRequest(ctx, req) {
		resp, auth, err = c.handleLoginRequest(ctx, req, false)
		te = req.TokenEntry()
	} else {
		resp, auth, err = c.handleNonLoginRequest(ctx, req)
		te = req.TokenEntry()
	}

	if resp != nil && resp.Streamed {
		if srw, ok := req.ResponseWriter.(*logical.StatusRecordingWriter); ok {
			var ctxErr error
			if req.HTTPRequest != nil {
				ctxErr = req.HTTPRequest.Context().Err()
			}
			resp.StatusCode = streamedStatusCode(srw.StatusCode(), ctxErr)
		}
	}

	// Create an audit trail of the response
	auditEntry := c.buildResponseAuditEntry(ctx, req, resp, auth, te, err)
	if auditOK, auditErr := c.auditManager.LogResponse(ctx, auditEntry); auditErr != nil {
		c.logger.Error("failed to audit response",
			logger.String("path", req.Path),
			logger.Err(auditErr),
		)
		// For non-streaming requests, audit failure = request failure
		if !req.Streamed {
			return nil, ErrInternalError
		}
	} else if !auditOK && !req.Streamed && !req.StreamUnauthenticated {
		// For non-streaming requests, block if no audit devices are configured.
		// Streaming requests are allowed through even without auditing because:
		// 1. The connection may already be established with data flowing
		// 2. Abruptly terminating would be more disruptive than missing audit
		// 3. The audit failure is still logged for operator awareness
		c.logger.Warn("response blocked: no audit devices configured",
			logger.String("path", req.Path),
		)
		return nil, ErrInternalError
	}

	return resp, err
}

func (c *Core) isLoginRequest(ctx context.Context, req *logical.Request) bool {
	return c.router.LoginPath(ctx, req.Path)
}

// handleLoginRequest is used to handle a login request, which is an
// unauthenticated request to the backend.
func (c *Core) handleLoginRequest(ctx context.Context, req *logical.Request, isInternalLogin bool) (retResp *logical.Response, retAuth *logical.Auth, retErr error) {

	req.Unauthenticated = true

	entry := c.router.MatchingMountEntry(ctx, req.Path)
	if entry != nil {
		// Set here so the audit log has it even if authorization fails
		req.MountType = entry.Type
		req.MountClass = entry.Class
		req.MountAccessor = entry.Accessor
	}

	// Parse request body before CheckToken since req.Data may be used during token validation.
	//
	// An internal login is exempt: its Data is not the caller's, it is the credential
	// and role this request's own auth precedence resolved, and the HTTP request it
	// carries belongs to the gateway call that triggered the login. Parsing here would
	// merge that caller's query params and body keys into the resolved map — a body of
	// {"role":"other"} or a ?role=other would pick the role the login authenticates
	// against, through a channel that never reaches req.Path and so is invisible to
	// both policy and the audit log.
	if !isInternalLogin {
		if err := c.parseRequestBody(req); err != nil {
			return logical.ErrorResponse(logical.ErrBadRequest(err.Error())), nil, err
		}
	}

	// Do an unauth check.
	var auth *logical.Auth
	//var cbp *CBP
	//var te *logical.TokenEntry
	var ctErr error
	auth, _, _, ctErr = c.CheckToken(ctx, req, true)

	if ctErr != nil {
		// If it is an internal error we return that, otherwise we
		// return invalid request so that the status codes can be correct
		var errType error
		switch ctErr {
		case ErrInternalError, sdklogical.ErrPermissionDenied:
			errType = ctErr
		default:
			errType = sdklogical.ErrInvalidRequest
		}

		// Audit the failed request
		auditEntry := c.buildRequestAuditEntry(ctx, req, auth, nil, ctErr)
		if _, auditErr := c.auditManager.LogRequest(ctx, auditEntry); auditErr != nil {
			c.logger.Error("failed to audit login request error",
				logger.String("path", req.Path),
				logger.Err(auditErr),
			)
		}

		if errType != nil {
			retErr = multierror.Append(retErr, errType)
		}

		// Build the error response for audit logging
		var resp *logical.Response
		if ctErr == ErrInternalError {
			resp = nil
		} else {
			resp = logical.ErrorResponse(logical.ErrInternal(ctErr.Error()))
		}

		// Audit the failed response - ensures complete request/response pair in audit log
		respAuditEntry := c.buildResponseAuditEntry(ctx, req, resp, auth, nil, ctErr)
		if _, auditErr := c.auditManager.LogResponse(ctx, respAuditEntry); auditErr != nil {
			c.logger.Error("failed to audit login failure response",
				logger.String("path", req.Path),
				logger.Err(auditErr),
			)
		}

		if ctErr == ErrInternalError {
			return nil, auth, retErr
		}
		return resp, auth, retErr
	}

	// Create an audit trail of the request
	auditEntry := c.buildRequestAuditEntry(ctx, req, auth, nil, nil)
	if auditOK, auditErr := c.auditManager.LogRequest(ctx, auditEntry); auditErr != nil {
		c.logger.Error("failed to audit login request",
			logger.String("path", req.Path),
			logger.Err(auditErr),
		)
		return nil, nil, ErrInternalError
	} else if !auditOK {
		c.logger.Warn("login request blocked: no audit devices configured",
			logger.String("path", req.Path),
		)
		return nil, nil, ErrInternalError
	}

	// Route the request
	resp, routeErr := c.doRouting(ctx, req)

	// If the response generated an authentication, then generate the token.
	// Transparent token types are reserved for the internal gateway auth flow
	// — reject explicit login attempts early. The set of transparent types is
	// determined by the registry rather than a hardcoded list so adding a new
	// transparent auth method does not require touching this guard.
	if resp != nil && resp.Auth != nil {
		if !isInternalLogin && c.tokenStore.IsTransparentType(resp.Auth.TokenType) {
			return logical.ErrorResponse(logical.ErrBadRequest("explicit login is not supported for roles with token_type=transparent; clients authenticate implicitly via gateway requests")), nil, nil
		} else {
			respTokenCreate, errCreateToken := c.LoginCreateToken(ctx, req, resp)
			if errCreateToken != nil {
				return respTokenCreate, nil, errCreateToken
			}
			resp = respTokenCreate
			resp.MountClass = req.MountClass
		}
	}

	if routeErr != nil {
		retErr = multierror.Append(retErr, routeErr)
	}

	return resp, auth, routeErr
}

func (c *Core) LoginCreateToken(ctx context.Context, req *logical.Request, resp *logical.Response) (*logical.Response, error) {
	auth := resp.Auth

	// Prevent internal policies from being assigned to tokens.
	for _, policy := range auth.Policies {
		if policy == "root" {
			return logical.ErrorResponse(logical.ErrForbidden("auth methods cannot create root tokens")), sdklogical.ErrInvalidRequest
		}
		if slices.Contains(nonAssignablePolicies, policy) {
			return logical.ErrorResponse(logical.ErrForbiddenf("cannot assign policy %q", policy)), sdklogical.ErrInvalidRequest
		}
	}

	// req.MountAccessor is populated by handleLoginRequest from the routed
	// mount entry. Carry it through so transparent token types can fold it
	// into their cache key (prevents cross-mount cache contamination when
	// two mounts of the same auth type have overlapping role names + the
	// same credential).
	var mountAccessor string
	if req != nil {
		mountAccessor = req.MountAccessor
	}

	now := time.Now()
	authData := logical.AuthData{
		PrincipalID:    auth.PrincipalID,
		RoleName:       auth.RoleName,
		ExpireAt:       now.Add(auth.TokenTTL),
		CredentialSpec: auth.CredentialSpec,
		Policies:       auth.Policies,
		ClientIP:       auth.ClientIP,
		TokenValue:     auth.ClientToken,
		MountAccessor:  mountAccessor,
		Actors:         auth.Actors,
		Metadata:       auth.Metadata,
	}

	tokenValue, err := c.tokenStore.GenerateToken(ctx, auth.TokenType, &authData)

	if err != nil {
		// error when creating token
		c.logger.Error("Failed to generate token", logger.String("token_type", auth.TokenType), logger.Any("auth_data", authData))
		return logical.ErrorResponse(logical.ErrInternal("failed to generate token")), ErrInternalError
	}

	data := map[string]any{
		"token_type":     authhelper.DisplayTokenType(tokenValue.Type, c.tokenStore.IsTransparentType(tokenValue.Type)),
		"expire_at":      tokenValue.ExpireAt,
		"bound_ip":       tokenValue.CreatedByIP,
		"token_id":       tokenValue.ID,
		"token_assessor": tokenValue.Accessor,
		"namespace":      tokenValue.NamespacePath,
		"principal_id":   tokenValue.PrincipalID,
		"role":           tokenValue.RoleName,
		"data":           tokenValue.Data,
		"policies":       tokenValue.Policies,
	}

	maps.Copy(resp.Data, data)

	// Remove internal fields that were needed for token generation
	// but should not be exposed to the client.
	delete(resp.Data, "fingerprint")

	resp.StatusCode = http.StatusCreated

	return resp, nil
}

func (c *Core) doRouting(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	return c.router.Route(ctx, req)
}

func (c *Core) handleNonLoginRequest(ctx context.Context, req *logical.Request) (retResp *logical.Response, retAuth *logical.Auth, retErr error) {
	entry := c.router.MatchingMountEntry(ctx, req.Path)
	if entry != nil {
		// Set here so the audit log has it even if authorization fails
		req.MountType = entry.Type
		req.MountClass = entry.Class
		req.MountAccessor = entry.Accessor
		req.MountPoint = entry.Path
	}

	// Parse request body before CheckToken since req.Data may be used during policy evaluation.
	// Help requests are never streaming - they should return help text, not proxy upstream.
	isStreaming := c.isStreamingRequest(ctx, req.Path) && req.Operation != logical.HelpOperation

	if !isStreaming {
		if err := c.parseRequestBody(req); err != nil {
			return logical.ErrorResponse(logical.ErrBadRequest(err.Error())), nil, err
		}
		req.ClientToken = extractToken(req.HTTPRequest)

		// Transparent operations: implicit auth on non-gateway endpoints.
		// Triggered when there's no explicit X-Warden-Token but an auth path
		// is configured on the namespace. The Authorization: Bearer value is
		// treated as a JWT credential, not a Warden token.
		// Auth role precedence: ?role= query param > X-Warden-Role header > auth method default_role.
		if req.HTTPRequest != nil && req.HTTPRequest.Header.Get("X-Warden-Token") == "" {
			var authPath string
			if ns, _ := namespace.FromContext(ctx); ns != nil {
				authPath = ns.CustomMetadata["auto_auth_path"]
			}
			if authPath != "" {
				var authRole string
				if role, ok := req.Data["role"].(string); ok {
					authRole = role
				} else {
					authRole = req.HTTPRequest.Header.Get("X-Warden-Role")
				}
				if err := c.performImplicitAuth(ctx, req, authPath, authRole); err != nil {
					c.logger.Warn("transparent operations auth failed",
						logger.Err(err),
						logger.String("path", req.Path),
						logger.String("auth_path", authPath),
					)
					return logical.ErrorResponse(logical.ErrUnauthorized(err.Error())), nil, nil
				}
			}
		}
	} else {
		req.Streamed = true

		// Set AuditPath for consistent audit logging between request and response entries.
		// For streaming requests, this is the path relative to the mount point
		// (e.g., "role/operator/gateway/v1/...") before routing transforms req.Path.
		if req.MountPoint != "" {
			req.AuditPath = strings.TrimPrefix(req.Path, req.MountPoint)
		} else {
			req.AuditPath = req.Path
		}

		matchingBackend := c.router.MatchingBackend(ctx, req.Path)
		if matchingBackend == nil {
			c.logger.Warn("no backend mounted at path",
				logger.String("full_req_path", req.HTTPRequest.URL.Path),
				logger.String("relative_req_path", req.Path),
			)
			return logical.ErrorResponse(logical.ErrNotFoundf("no handler for path %q", req.Path)), nil, logical.ErrNotFoundf("no handler for path %q", req.Path)
		}

		// Opt-in body parsing for streaming requests.
		// Backends that implement StreamBodyParser and return true get req.Data
		// populated before policy evaluation. The body is restored after parsing
		// so the streaming handler can still read it.
		if parser, ok := matchingBackend.(logical.StreamBodyParser); ok && parser.ShouldParseStreamBody(req.HTTPRequest) {
			if err := c.parseRequestBody(req); err != nil {
				return logical.ErrorResponse(logical.ErrBadRequest(err.Error())), nil, err
			}
		}

		// MCP body-authoritative policy enforcement: when the routed
		// backend opts into logical.MCPPolicyEnforced, buffer the
		// request body and strict-parse it into a descriptor before
		// CheckToken runs. The extractor restores the body so the
		// downstream proxy reads it unchanged. Non-MCP backends fail
		// the type assertion and skip the extractor entirely.
		c.extractMCPDescriptor(ctx, req, matchingBackend)

		// Resolve the secondary (user) auth config once, before extraction:
		// whether this mount is a protected resource decides how the extractor
		// reads Authorization. On a mount with no effective user_auth_path the
		// rule collapses to the pre-0.20 behaviour and userCred stays empty.
		userAuthPath, userAuthRole := c.resolveUserAuthConfig(ctx, matchingBackend)
		userLeg := userAuthPath != ""

		// Reject the one genuinely ambiguous credential combination rather than
		// resolving it silently. X-Warden-Token is the operator credential and
		// never carries a user (see logical.ExtractTokensDefault), while on a
		// protected-resource mount Authorization is where the user rides. A
		// request bearing both is mixing the operator and workload surfaces:
		// whichever way the provider's precedence falls, one of the two
		// credentials gets dropped without comment. Say so instead.
		//
		// Presenting X-Warden-Token alone stays valid — that is explicit
		// (non-transparent) agent auth, and it works here exactly as it does on
		// a mount that is not a protected resource.
		if userLeg && req.HTTPRequest != nil &&
			req.HTTPRequest.Header.Get(logical.HeaderWardenToken) != "" &&
			req.HTTPRequest.Header.Get("Authorization") != "" {
			c.logger.Warn("ambiguous credentials on a protected-resource mount",
				logger.String("path", req.Path),
				logger.String("request_id", req.RequestID),
			)
			return logical.ErrorResponse(logical.ErrBadRequest(
				"X-Warden-Token cannot be combined with an Authorization credential on a mount " +
					"with user_auth_path: it is the operator credential and carries no user principal. " +
					"Present the agent via X-Warden-Agent-Token or a client certificate to let " +
					"Authorization carry the user, or drop the Authorization header.")), nil, nil
		}

		var userCred string
		req.ClientToken, userCred = matchingBackend.ExtractTokens(req.HTTPRequest, userLeg)

		// Check for unauthenticated paths on streaming backends.
		//
		// A user credential is what makes passthrough unsafe: it would skip
		// CheckToken, minting, user capture and audit for a principal we must
		// record. A credential-less probe mints and injects nothing, so it
		// still passes through — git's opening info/refs carries no
		// Authorization and needs the upstream's challenge to learn to retry
		// with one. Providers declaring unauthenticated paths must therefore
		// surface Authorization-borne user credentials from ExtractTokens.
		if req.ClientToken == "" && userCred == "" {
			if tmp, ok := matchingBackend.(logical.TransparentModeProvider); ok {
				relativePath := req.Path
				if req.MountPoint != "" {
					relativePath = strings.TrimPrefix(req.Path, req.MountPoint)
				}
				if tmp.IsUnauthenticatedPath(req.HTTPRequest, relativePath) {
					req.StreamUnauthenticated = true
					c.logger.Trace("unauthenticated streaming request",
						logger.String("path", req.Path),
					)
				}
			}
		}

		// Perform implicit auth if needed
		// Skip if already marked as unauthenticated (handled above)
		if !req.StreamUnauthenticated {
			if isTransparent, role := c.isTransparentRequest(req, matchingBackend); isTransparent {
				if err := c.handleTransparentAuth(ctx, req, matchingBackend, role); err != nil {
					c.logger.Warn("implicit authentication failed",
						logger.Err(err),
						logger.String("path", req.Path),
						logger.String("operation", string(req.Operation)),
						logger.String("request_id", req.RequestID),
					)

					errResp := logical.ErrorResponse(logical.ErrUnauthorized(err.Error()))
					attachGitBasicChallenge(req, errResp)
					return errResp, nil, nil
				}
			}
		}

		// Secondary transparent authentication: validate the per-request USER
		// principal (identity only) already extracted above, when the provider
		// or namespace configures user_auth_path. It runs upfront — before
		// CheckToken and thus before the CBP decision — so the user is a
		// first-class, already-validated principal by the time authorization and
		// minting run. Skipped for stream-unauthenticated requests, which bypass
		// CheckToken, minting, and audit entirely.
		if !req.StreamUnauthenticated {
			if err := c.captureUserContext(ctx, req, userAuthPath, userAuthRole, userCred); err != nil {
				c.logger.Warn("secondary user authentication failed",
					logger.Err(err),
					logger.String("path", req.Path),
					logger.String("request_id", req.RequestID),
				)
				// A user credential WAS presented and rejected, so the challenge
				// carries error="invalid_token" — the client should replace it
				// rather than assume it simply forgot to send one.
				errResp := logical.ErrorResponse(logical.ErrUnauthorized(err.Error()))
				c.attachUserChallenge(ctx, req, errResp, true)
				return errResp, nil, nil
			}
		}
	}

	var auth *logical.Auth
	var te *logical.TokenEntry

	// Validate the token (non-login requests require authentication)
	// Skip for unauthenticated streaming paths
	if !req.StreamUnauthenticated {
		var ctErr error
		auth, _, te, ctErr = c.CheckToken(ctx, req, false)
		if ctErr != nil {
			// A permission denial is an expected authorization outcome, not an
			// operational fault, and is already recorded in full in the audit
			// log — so it is kept out of the operational log entirely (even at
			// debug), or an MCP client probing capabilities (e.g. prompts/list
			// under a policy that doesn't allow it) would spam it. Genuine
			// failures (internal errors, malformed requests) still warn.
			permDenied := errwrap.Contains(ctErr, sdklogical.ErrPermissionDenied.Error()) &&
				!errwrap.Contains(ctErr, ErrInternalError.Error())
			if !permDenied {
				c.logger.Warn("error when checking token", logger.Err(ctErr))
			}
			switch {
			case ctErr == ErrInternalError,
				errwrap.Contains(ctErr, ErrInternalError.Error()),
				ctErr == sdklogical.ErrPermissionDenied,
				errwrap.Contains(ctErr, sdklogical.ErrPermissionDenied.Error()):
				switch ctErr.(type) {
				case *multierror.Error:
					retErr = ctErr
				default:
					retErr = multierror.Append(retErr, ctErr)
				}
			default:
				retErr = multierror.Append(retErr, sdklogical.ErrInvalidRequest)
			}

			// Audit the failed request even for internal errors
			auditEntry := c.buildRequestAuditEntry(ctx, req, auth, te, ctErr)
			if _, auditErr := c.auditManager.LogRequest(ctx, auditEntry); auditErr != nil {
				c.logger.Error("failed to audit token check failure",
					logger.String("path", req.Path),
					logger.Err(auditErr),
				)
			}

			// Build the error response
			var resp *logical.Response
			if errwrap.Contains(retErr, ErrInternalError.Error()) {
				resp = nil
			} else {
				resp = logical.ErrorResponse(ctErr)
			}

			// Audit the failed response
			respAuditEntry := c.buildResponseAuditEntry(ctx, req, resp, auth, te, ctErr)
			if _, auditErr := c.auditManager.LogResponse(ctx, respAuditEntry); auditErr != nil {
				c.logger.Error("failed to audit token check failure response",
					logger.String("path", req.Path),
					logger.Err(auditErr),
				)
			}

			if errwrap.Contains(retErr, ErrInternalError.Error()) {
				return nil, auth, retErr
			}
			return resp, auth, retErr
		}
	}

	// Create an audit trail of the request.
	// Skip for unauthenticated streaming paths (e.g., public PKI certificates) because:
	// 1. No authentication context exists - no token, principal, or policies to audit
	// 2. These paths are explicitly marked as public by the backend
	// 3. High-volume public requests would create audit log noise without security value
	if !req.StreamUnauthenticated {
		auditEntry := c.buildRequestAuditEntry(ctx, req, auth, te, nil)
		if auditOK, auditErr := c.auditManager.LogRequest(ctx, auditEntry); auditErr != nil {
			c.logger.Error("failed to audit request",
				logger.String("path", req.Path),
				logger.Err(auditErr),
			)
			retErr = multierror.Append(retErr, ErrInternalError)
			return nil, auth, retErr
		} else if !auditOK {
			c.logger.Warn("request blocked: no audit devices configured",
				logger.String("path", req.Path),
			)
			retErr = multierror.Append(retErr, ErrInternalError)
			return nil, auth, retErr
		}
	}

	// For streaming requests, mint credentials (unless StreamUnauthenticated)
	if req.Streamed && !req.StreamUnauthenticated {
		if err := c.mintCredentialForRequest(ctx, req, te); err != nil {
			c.logger.Error("failed to mint credential for streaming request",
				logger.Err(err),
				logger.String("path", req.Path),
			)
			errResp := logical.ErrorResponse(err)
			c.attachUserRequiredChallenge(ctx, req, errResp, err)
			return errResp, auth, nil
		}
	}

	// Route the request
	resp, routeErr := c.doRouting(ctx, req)

	// A non-login request should not return an auth block
	if resp != nil && resp.Auth != nil {
		c.logger.Error("unexpected Auth response for non-login backend", logger.String("request_path", req.Path))
		retErr = multierror.Append(retErr, ErrInternalError)
		return nil, auth, retErr
	}

	// Access backend returned AccessData → mint credential + let backend format response
	if resp != nil && resp.AccessData != nil {
		ad := resp.AccessData
		if te == nil {
			c.logger.Error("AccessData returned but no token entry", logger.String("path", req.Path))
			retErr = multierror.Append(retErr, ErrInternalError)
			return nil, auth, retErr
		}
		te.CredentialSpec = ad.CredentialSpec
		if err := c.mintCredentialForRequest(ctx, req, te); err != nil {
			c.logger.Error("failed to mint credential for access request",
				logger.Err(err), logger.String("path", req.Path))
			return logical.ErrorResponse(accessPathMintError(err)), auth, nil
		}
		resp.Data = ad.ResponseBuilder(req.Credential)
		resp.AccessData = nil
	}

	// Return the response and error
	if routeErr != nil {
		retErr = multierror.Append(retErr, routeErr)
	}

	if resp != nil {
		resp.MountClass = req.MountClass
	}

	return resp, auth, retErr

}

// PopulateTokenEntry looks up req.ClientToken in the token store and uses
// it to set other fields in req.  Does nothing if ClientToken is empty
// or for tokens that don't exist in the token store.
// Should be called with read stateLock held.
func (c *Core) PopulateTokenEntry(ctx context.Context, req *logical.Request) error {
	if req.ClientToken == "" {
		return nil
	}

	token := req.ClientToken

	// Inject client IP into context so validateIPBinding can read it
	if req.ClientIP != "" {
		ctx = context.WithValue(ctx, logical.ClientIPKey, req.ClientIP)
	}

	te, err := c.LookupToken(ctx, token)
	if err == nil && te != nil {
		req.ClientTokenAccessor = te.Accessor
		req.ClientTokenID = te.ID
		req.SetTokenEntry(te)
	}
	return nil
}

// isStreamingRequest checks if the request path is a streaming path
func (c *Core) isStreamingRequest(ctx context.Context, path string) bool {
	return c.router.StreamingPath(ctx, path)
}

// parseRequestBody parses query params and JSON body into req.Data
func (c *Core) parseRequestBody(req *logical.Request) error {
	if req.HTTPRequest == nil {
		return nil
	}

	// Initialize Data map
	if req.Data == nil {
		req.Data = make(map[string]any)
	}

	// Parse query params first
	for k, v := range req.HTTPRequest.URL.Query() {
		if len(v) == 1 {
			req.Data[k] = v[0]
		} else {
			req.Data[k] = v
		}
	}

	// For GET/DELETE/HEAD - query params only, no body
	method := req.HTTPRequest.Method
	if method == http.MethodGet || method == http.MethodDelete || method == http.MethodHead {
		return nil
	}

	// Parse body based on Content-Type (overwrites query params with same keys)
	return c.parseBody(req)
}

// parseBody dispatches to the appropriate body parser based on Content-Type.
// Supports application/json and application/x-www-form-urlencoded.
// Unknown content types are silently skipped (body left untouched).
func (c *Core) parseBody(req *logical.Request) error {
	contentType := req.HTTPRequest.Header.Get("Content-Type")

	switch {
	case strings.HasPrefix(contentType, "application/json") || contentType == "":
		return c.parseJSONBody(req)
	case strings.HasPrefix(contentType, "application/x-www-form-urlencoded"):
		return c.parseFormBody(req)
	default:
		return nil
	}
}

// parseJSONBody parses the JSON body of the request into req.Data
func (c *Core) parseJSONBody(req *logical.Request) error {
	if req.HTTPRequest.Body == nil {
		return nil
	}

	contentType := req.HTTPRequest.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/json") && contentType != "" {
		return nil // Not JSON, skip
	}

	body, err := io.ReadAll(io.LimitReader(req.HTTPRequest.Body, maxRequestBodySize+1))
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	req.HTTPRequest.Body.Close()

	if int64(len(body)) > maxRequestBodySize {
		return fmt.Errorf("request body exceeds maximum size of %d bytes", maxRequestBodySize)
	}

	// Restore body for potential re-reading (audit, streaming, etc.)
	req.HTTPRequest.Body = io.NopCloser(bytes.NewReader(body))

	if len(body) == 0 {
		return nil
	}

	return json.Unmarshal(body, &req.Data)
}

// parseFormBody parses application/x-www-form-urlencoded body into req.Data.
// Like parseJSONBody, it reads the body with a size limit and restores it for re-reading.
func (c *Core) parseFormBody(req *logical.Request) error {
	if req.HTTPRequest.Body == nil {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(req.HTTPRequest.Body, maxRequestBodySize+1))
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	req.HTTPRequest.Body.Close()

	if int64(len(body)) > maxRequestBodySize {
		return fmt.Errorf("request body exceeds maximum size of %d bytes", maxRequestBodySize)
	}

	// Restore body for potential re-reading (audit, streaming, etc.)
	req.HTTPRequest.Body = io.NopCloser(bytes.NewReader(body))

	if len(body) == 0 {
		return nil
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return fmt.Errorf("failed to parse form body: %w", err)
	}

	for k, v := range values {
		if len(v) == 1 {
			req.Data[k] = v[0]
		} else {
			req.Data[k] = v
		}
	}

	return nil
}

// maxAssertionMetadataBytes bounds the JSON size of the metadata projected into a
// warden_identity assertion. The assertion is a bearer token presented to a
// third-party upstream (STS, an OAuth endpoint) that enforces its own token-size
// limits, so an oversized projection fails closed here rather than breaking the
// exchange downstream.
const maxAssertionMetadataBytes = 4 * 1024

// projectAssertionMetadata selects the operator-allowlisted keys from the token's
// login-derived metadata for embedding in a warden_identity assertion. Absent keys
// are skipped (as the auth-method extractors do). It returns the projected map plus
// a canonical fingerprint fragment (the marshalled JSON, whose object keys Go sorts
// deterministically) that isolates the credential cache per distinct projected
// metadata, so two tokens sharing subject+audience but differing in projected
// metadata never share a cached upstream credential. It fails closed when the
// projection exceeds maxAssertionMetadataBytes.
func projectAssertionMetadata(md map[string]string, keys []string) (map[string]string, string, error) {
	if len(keys) == 0 || len(md) == 0 {
		return nil, "", nil
	}
	projected := make(map[string]string, len(keys))
	for _, k := range keys {
		if v, ok := md[k]; ok {
			projected[k] = v
		}
	}
	if len(projected) == 0 {
		return nil, "", nil
	}
	encoded, err := json.Marshal(projected)
	if err != nil {
		return nil, "", fmt.Errorf("marshal assertion metadata: %w", err)
	}
	if len(encoded) > maxAssertionMetadataBytes {
		return nil, "", fmt.Errorf("assertion metadata exceeds %d bytes", maxAssertionMetadataBytes)
	}
	return projected, string(encoded), nil
}

// projectUserClaims selects the operator-allowlisted keys from the secondary
// (user) principal's login-derived metadata for the nested warden_user assertion
// claim and for per-user secret_path templating. Unlike projectAssertionMetadata it
// FAILS CLOSED on an absent key: warden_user scopes a security-sensitive downstream
// path (a templated policy / a per-user secret path), so a named-but-missing claim
// must deny rather than silently widen the scope. Returns the projected map, which
// is empty-key → nil.
func projectUserClaims(md map[string]string, keys []string) (map[string]string, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	projected := make(map[string]string, len(keys))
	for _, k := range keys {
		v, ok := md[k]
		if !ok {
			return nil, fmt.Errorf("assertion_user_claims names %q but the user token has no such claim", k)
		}
		projected[k] = v
	}
	encoded, err := json.Marshal(projected)
	if err != nil {
		return nil, fmt.Errorf("marshal user claims: %w", err)
	}
	if len(encoded) > maxAssertionMetadataBytes {
		return nil, fmt.Errorf("user claims exceed %d bytes", maxAssertionMetadataBytes)
	}
	return projected, nil
}

// resolveExchangeInputs derives the token-exchange inputs for the named spec on
// this request. specName is passed explicitly (rather than taken from te) so it can
// resolve inputs for a spec other than the caller's bound one — credential chaining
// reuses it to mint a referenced secret-spec as the same caller. It returns
// (nil, nil) when the spec does not opt into exchange, so the non-exchange mint path
// is completely unaffected.
//
// Every forwarded token is trusted at the source — a Warden-minted assertion, the
// agent's verified inbound JWT, or the user's auth-method-validated credential — so
// the driver forwards it without re-validating. Every configured-but-missing input
// fails the request closed rather than silently minting a non-exchange credential.
//
// A warden_identity subject or actor defers its assertion mint to a
// credential-cache miss (via inputs.ResolveSubjectToken / ResolveActorToken) so a
// cache hit pays no signing cost; the issuer-ready and audience checks stay eager
// and fail closed. The subject and actor resolve independently — an eager
// user_identity subject can pair with a lazily-minted warden_identity actor.
func (c *Core) resolveExchangeInputs(ctx context.Context, req *logical.Request, te *logical.TokenEntry, specName string) (*credential.ExchangeInputs, error) {
	spec, err := c.credConfigStore.GetSpec(ctx, specName)
	if err != nil {
		return nil, fmt.Errorf("failed to load credential spec: %w", err)
	}
	if !credential.SpecRequestsExchange(spec.Config) {
		return nil, nil
	}

	inputs := &credential.ExchangeInputs{
		SubjectTokenType: spec.Config[credential.ConfigSubjectTokenType],
		ActorTokenType:   spec.Config[credential.ConfigActorTokenType],
	}
	if inputs.SubjectTokenType == "" {
		inputs.SubjectTokenType = credential.TokenTypeJWT
	}

	// loadSource fetches the spec's source at most once per request, only when a
	// warden_identity subject or actor derivation actually needs it (an unset
	// audience or unset assertion_resource). Shared across both switches so a spec
	// that derives from the source loads it once, not twice.
	var srcCached *credential.CredSource
	loadSource := func() (*credential.CredSource, error) {
		if srcCached == nil {
			s, err := c.credConfigStore.GetSource(ctx, spec.Source)
			if err != nil {
				return nil, fmt.Errorf("spec %q: failed to load source %q: %w", specName, spec.Source, err)
			}
			srcCached = s
		}
		return srcCached, nil
	}

	// The secondary (user) principal, when the request captured one, feeds the
	// warden_user assertion claim and per-user secret_path templating. Read from the
	// request — the same object the chaining closure captures, so it is present for a
	// chained secret-spec too.
	var userTE *logical.TokenEntry
	if req.User != nil {
		userTE = req.User.TokenEntry
	}

	switch spec.Config[credential.ConfigSubjectTokenSource] {
	case credential.SourceAgentIdentity:
		// Reuse the JWT Warden verified during inbound authentication. It lives
		// in ClientToken only for transparent JWT auth; an opaque session token
		// or a cert-authenticated request has no reusable JWT and fails closed.
		if !strings.HasPrefix(req.ClientToken, "eyJ") {
			return nil, fmt.Errorf("spec %q requires an inbound JWT subject token but the request was not JWT-authenticated", specName)
		}
		inputs.SubjectToken = req.ClientToken
	case credential.SourceUserIdentity:
		// Forward the secondary (user) principal's own validated credential as the
		// RFC 8693 subject_token — the standard "agent acting for a user" delegation.
		// The credential was validated by the user's auth method (PR1), so Warden
		// forwards it as-is. Fail closed when no user principal was captured: this is
		// spec-opt-in delegation, never a silent fallback to the agent's identity.
		if req.User == nil || req.User.RawToken == "" {
			return nil, fmt.Errorf("spec %q requires subject_token_source=user_identity: %w", specName, credential.ErrUserRequired)
		}
		inputs.SubjectToken = req.User.RawToken
	case credential.SourceWardenIdentity:
		// Warden mints a fresh, short-lived assertion of the caller's resolved
		// identity as the subject (Workload Identity Federation) — Warden signed it.
		// Minted lazily on a cache miss; fails closed if the issuer is
		// disabled/not-ready or no audience is available.
		setup, err := c.buildAssertionSetup(ctx, specName, spec, te, userTE, loadSource)
		if err != nil {
			return nil, err
		}
		inputs.SubjectTokenType = credential.TokenTypeJWT
		inputs.SubjectCacheIdentity = setup.cacheIdentity
		inputs.ResolveSubjectToken = setup.resolve
		// Surface the projected user claims so the driver can template a per-user
		// request (e.g. kv2_read's secret_path) — the same projection embedded in the
		// assertion's warden_user claim. Nil unless the spec set assertion_user_claims.
		inputs.UserClaims = setup.userClaims
	default:
		// SpecRequestsExchange already excluded "none"/absent; any other value
		// (including a persisted, now-retired "header") fails closed at mint.
		return nil, fmt.Errorf("spec %q has an unsupported %s %q", specName, credential.ConfigSubjectTokenSource, spec.Config[credential.ConfigSubjectTokenSource])
	}

	switch spec.Config[credential.ConfigActorTokenSource] {
	case credential.SourceAgentIdentity:
		// The agent's verified inbound JWT acts as the actor (agent-acting-for-user).
		// Requires JWT auth; spec validation forbids subject_token_source=agent_identity
		// alongside it, so ClientToken is free to serve as the actor.
		if !strings.HasPrefix(req.ClientToken, "eyJ") {
			return nil, fmt.Errorf("spec %q requires an inbound JWT actor token but the request was not JWT-authenticated", specName)
		}
		inputs.ActorToken = req.ClientToken
		if inputs.ActorTokenType == "" {
			inputs.ActorTokenType = credential.TokenTypeJWT
		}
	case credential.SourceWardenIdentity:
		// Delegation: Warden signs the agent as the RFC 8693 actor (act), acting on
		// behalf of the user carried in the user_identity subject (spec validation
		// requires subject_token_source=user_identity here). Minted lazily on a cache
		// miss, like the subject assertion.
		setup, err := c.buildAssertionSetup(ctx, specName, spec, te, userTE, loadSource)
		if err != nil {
			return nil, err
		}
		inputs.ActorTokenType = credential.TokenTypeJWT
		inputs.ActorCacheIdentity = setup.cacheIdentity
		inputs.ResolveActorToken = setup.resolve
		inputs.UserClaims = setup.userClaims
	case credential.SourceNone, "":
		// No actor requested: drop any default type so Validate's pairing holds.
		inputs.ActorTokenType = ""
	default:
		// A persisted spec with a retired actor source (e.g. "header") reaches here
		// at mint time — fail closed rather than silently minting without delegation.
		return nil, fmt.Errorf("spec %q has an unsupported %s %q", specName, credential.ConfigActorTokenSource, spec.Config[credential.ConfigActorTokenSource])
	}

	if err := inputs.Validate(); err != nil {
		return nil, err
	}
	return inputs, nil
}

// assertionSetup holds the parts resolveExchangeInputs needs to configure a
// warden_identity slot (subject or actor): a stable cache fragment that keys the
// credential cache in place of the per-request-volatile assertion bytes, the
// closure that mints the assertion lazily on a cache miss, and the projected
// secondary-user claims (empty when the spec discloses no user) that a driver
// templates its per-user request from.
type assertionSetup struct {
	cacheIdentity string
	resolve       func(ctx context.Context) (string, error)
	// userClaims is the projected assertion_user_claims map (the same values
	// embedded in the assertion's warden_user claim), surfaced so the driver can
	// template a per-user path from them. Nil when the spec sets no
	// assertion_user_claims.
	userClaims map[string]string
}

// buildAssertionSetup validates the OIDC issuer is ready and derives the
// audience, resource, and projected metadata for a warden_identity assertion of
// te, returning a stable cache fragment (identity + audience [+ resource]
// [+ metadata]) and a lazy mint closure. It is source-type agnostic, so the same
// setup serves a WIF subject (the agent IS the identity) and a delegation actor
// (the agent acts for the subject-header user). loadSource is passed in so the
// spec's source is fetched at most once per request across both slots.
//
// It fails closed if the issuer is disabled/not-ready or no audience can be
// determined. The audience is an explicit spec value or, failing that, one
// derived from the source; resource is unset→derived, "none"→omitted, else
// verbatim; metadata is the operator-allowlisted projection (empty→no claim, so
// the cache key is byte-identical to the no-metadata case).
func (c *Core) buildAssertionSetup(ctx context.Context, specName string, spec *credential.CredSpec, te *logical.TokenEntry, userTE *logical.TokenEntry, loadSource func() (*credential.CredSource, error)) (*assertionSetup, error) {
	issuer := c.OIDCIssuer()
	if issuer == nil || !issuer.Ready() {
		return nil, fmt.Errorf("spec %q requires warden_identity but the OIDC issuer is not enabled/ready", specName)
	}

	// The assertion audience: an explicit spec value wins; otherwise derive it
	// from the source (e.g. a GCP federation source derives it from its
	// workload_identity_provider). Fails closed if neither yields one.
	audience := spec.Config[credential.ConfigAssertionAudience]
	if audience == "" {
		src, err := loadSource()
		if err != nil {
			return nil, err
		}
		audience, _ = drivers.DeriveAssertionAudience(src.Type, src.Config, spec.Config)
	}
	if audience == "" {
		return nil, fmt.Errorf("spec %q with warden_identity requires %s", specName, credential.ConfigAssertionAudience)
	}

	// Resolve the single downstream resource to name in the assertion so a
	// verifier can pin it to one resource. Unset derives it from the source/spec
	// config (pure, network-free — no live driver is built here); "none" opts out;
	// any other value is emitted verbatim. Best-effort: a spec with no single
	// static resource simply carries no warden_resource claim.
	var resource string
	switch r := spec.Config[credential.ConfigAssertionResource]; r {
	case credential.AssertionResourceNone:
		// opt-out: emit no warden_resource claim
	case "":
		src, err := loadSource()
		if err != nil {
			return nil, err
		}
		resource, _ = drivers.DeriveAssertionResource(src.Type, src.Config, spec.Config)
	default:
		resource = r
	}

	// Project only the operator-allowlisted metadata keys into the assertion.
	// Empty allowlist projects nothing (mdFingerprint is ""), so the assertion and
	// cache key are byte-for-byte what they were before this opt-in existed.
	projected, mdFingerprint, err := projectAssertionMetadata(te.Metadata, credential.AssertionMetadataKeys(spec.Config))
	if err != nil {
		return nil, fmt.Errorf("spec %q: %w", specName, err)
	}

	// Project the secondary (user) principal into the nested warden_user claim, but
	// only when the spec opts into disclosure via assertion_user_claims — like
	// assertion_metadata_claims, a spec that does not ask never leaks user identity
	// into its assertion. When it asks, a user principal MUST be present and every
	// named claim MUST resolve; both fail closed, since warden_user scopes a
	// security-sensitive downstream path. userClaims (the projected values) is
	// surfaced on the setup so a driver can template a per-user path from it; the
	// assertion's warden_user additionally carries the user's original sub (the raw
	// principal, as warden_sub does for the agent — never the Warden composite).
	// Per-user cache isolation is the manager's ":u:" token-id dimension, so the
	// user does not enter cacheIdentity here.
	var userClaims map[string]string
	if userKeys := credential.AssertionUserClaimKeys(spec.Config); len(userKeys) > 0 {
		if userTE == nil {
			return nil, fmt.Errorf("spec %q sets assertion_user_claims: %w", specName, credential.ErrUserRequired)
		}
		// "sub" names the user's identity principal, not a metadata key — exclude it
		// from the metadata projection so an operator can list it (to bind
		// warden_user.sub / template {{user.sub}}) without needing a metadata key
		// literally named "sub". Listing only "sub" yields an identity-only warden_user.
		metaKeys := make([]string, 0, len(userKeys))
		for _, k := range userKeys {
			if k != "sub" {
				metaKeys = append(metaKeys, k)
			}
		}
		projectedUser, perr := projectUserClaims(userTE.Metadata, metaKeys)
		if perr != nil {
			return nil, fmt.Errorf("spec %q: %w", specName, perr)
		}
		// One warden_user map serves BOTH the assertion claim and secret_path
		// templating, so {{user.sub}} templates exactly the value the policy binds.
		// The identity sub (the raw principal) is authoritative and set last.
		userClaims = make(map[string]string, len(projectedUser)+1)
		for k, v := range projectedUser {
			userClaims[k] = v
		}
		userClaims["sub"] = userTE.PrincipalID
	}

	// Key the credential cache on the stable identity + audience, NOT the
	// freshly-minted assertion bytes (which change every request), so one identity
	// reuses its cached upstream credential. Fold in the resource (it can come from
	// source config, which can change under a fixed specName) and the projected-
	// metadata fingerprint. Each fragment is appended only when non-empty, so the
	// no-resource / no-metadata cache keys stay byte-for-byte unchanged; the
	// resource fragment is kept before mdFingerprint (marshalled JSON starting with
	// '{') so the fragments can never be confused.
	cacheIdentity := wardenSubject(te) + "\x00" + audience
	if resource != "" {
		cacheIdentity += "\x00res=" + resource
	}
	if mdFingerprint != "" {
		cacheIdentity += "\x00" + mdFingerprint
	}

	// The spec selects the assertion signing algorithm (default RS256). The issuer
	// maintains a keyset per algorithm, so either is available with no cold start;
	// validation restricts it to a supported alg at spec-create. The mint itself is
	// deferred to a cache MISS (invoked by the Manager's singleflight leader), so at
	// most one assertion is minted per miss and none on the hot path.
	alg := credential.AssertionAlgorithm(spec.Config)
	return &assertionSetup{
		cacheIdentity: cacheIdentity,
		userClaims:    userClaims,
		resolve: func(ctx context.Context) (string, error) {
			return issuer.MintIdentityAssertion(ctx, te, AssertionClaims{
				Audience:   audience,
				TTL:        issuer.AssertionTTL(),
				Alg:        alg,
				Metadata:   projected,
				Resource:   resource,
				UserClaims: userClaims,
			})
		},
	}, nil
}

// mintCredentialForRequest mints credentials for requests using the credential manager
func (c *Core) mintCredentialForRequest(ctx context.Context, req *logical.Request, te *logical.TokenEntry) error {
	if te == nil {
		return logical.ErrInternal("cannot mint credential since token entry is nil")
	}
	if te.CredentialSpec == "" {
		c.logger.Debug("no credential spec for token",
			logger.String("token_id", te.ID),
		)
		return logical.ErrBadRequest("cannot mint credential since no credential spec is bound to the token")
	}

	// Skip if credential manager not initialized
	if c.credentialManager == nil {
		return logical.ErrInternal("credential manager not initialized")
	}

	// Validate credential spec exists before attempting to issue
	if !c.credentialManager.SpecExists(ctx, te.CredentialSpec) {
		c.logger.Warn("credential spec not found or disabled",
			logger.String("token_id", te.ID),
			logger.String("spec_name", te.CredentialSpec),
		)
		return logical.ErrBadRequestf("credential spec %q not found or disabled", te.CredentialSpec)
	}

	// Calculate token TTL for cache duration
	var tokenTTL time.Duration
	if !te.ExpireAt.IsZero() {
		tokenTTL = time.Until(te.ExpireAt)
		if tokenTTL <= 0 {
			return fmt.Errorf("token has expired")
		}
	} else {
		// Default TTL for tokens without expiration
		tokenTTL = 1 * time.Hour
	}

	// Identify the secondary (user) principal to the mint pipeline for per-user
	// credential chaining (identity only). Only the user token id and TTL cross into
	// the credential package — the token id is the ":u:" cache dimension, and the
	// manager bounds the credential's cache duration by BOTH principals' TTLs so
	// revoking or expiring EITHER stops new mints. The user TTL is computed exactly
	// like the agent's above (1h default for a non-expiring token; expired is an
	// error). The user's identity/metadata are read from req.User where they are
	// consumed (the warden_user assertion), not duplicated here.
	var userCtx *credential.UserContext
	if req.User != nil && req.User.TokenEntry != nil {
		ute := req.User.TokenEntry
		var userTTL time.Duration
		if !ute.ExpireAt.IsZero() {
			userTTL = time.Until(ute.ExpireAt)
			if userTTL <= 0 {
				return fmt.Errorf("user token has expired")
			}
		} else {
			userTTL = 1 * time.Hour
		}
		userCtx = &credential.UserContext{TokenID: ute.ID, TokenTTL: userTTL}
	}

	// The caller carries the requesting identity through the mint pipeline so a
	// chained secret-spec (credential chaining) is minted as this same caller.
	// ResolveInputs resolves token-exchange inputs for an arbitrary spec as this
	// caller (nil for non-exchange specs), reused both for the outer spec below and
	// for any referenced secret-spec by the Manager.
	caller := credential.Caller{
		TokenID:  te.ID,
		TokenTTL: tokenTTL,
		User:     userCtx,
		ResolveInputs: func(ctx context.Context, specName string) (*credential.ExchangeInputs, error) {
			return c.resolveExchangeInputs(ctx, req, te, specName)
		},
	}

	// Resolve any caller-supplied token-exchange inputs the spec opts into.
	// Returns nil for non-exchange specs, leaving the mint path unchanged.
	inputs, err := caller.ResolveInputs(ctx, te.CredentialSpec)
	if err != nil {
		return exchangeInputError(err)
	}

	// Issue credential using the credential manager
	// Credentials are cache-only (not persisted) - ExpirationEntry handles lease revocation
	cred, err := c.credentialManager.IssueCredential(ctx, caller, te.CredentialSpec, inputs)
	if err != nil {
		return fmt.Errorf("failed to issue credential: %w", err)
	}

	// Inject credential into request
	req.Credential = cred

	return nil
}

// extractToken resolves the agent credential for a NON-streaming request. It
// checks X-Warden-Token first, then falls back to Authorization: Bearer.
//
// The two-principal rule deliberately does not apply here: nothing on the
// non-streaming path consumes a user credential (captureUserContext runs only in
// the streaming branch), so reinterpreting Authorization would change agent
// resolution — on provider config paths and transparent operations alike —
// while producing a user nobody reads. Streaming gateway requests use the
// routed backend's ExtractTokens instead.
func extractToken(r *http.Request) string {
	// Try X-Warden-Token header first
	if token := r.Header.Get(logical.HeaderWardenToken); token != "" {
		return token
	}
	// Fall back to Authorization: Bearer
	return stripBearer(r.Header.Get("Authorization"))
}

// stripBearer returns the token in an Authorization-style header value, matching
// the "Bearer " scheme case-insensitively and returning the remainder verbatim
// (no TrimSpace). It delegates to logical.StripBearer, the single source of
// truth for the strip, so core and every provider extractor agree byte-for-byte
// on where a token starts.
func stripBearer(authHeader string) string {
	return logical.StripBearer(authHeader)
}

// isTransparentRequest checks if this request needs implicit authentication.
// Returns true and the role name if the backend supports implicit auth,
// has an auth config, and the path is a gateway path.
// The role may be empty if no role is in the URL and no default role is configured.
func (c *Core) isTransparentRequest(req *logical.Request, backend logical.Backend) (bool, string) {
	// Check if backend supports implicit auth
	tmp, ok := backend.(logical.TransparentModeProvider)
	if !ok {
		return false, ""
	}

	// Check if auth config is set
	if !tmp.IsTransparentMode() {
		return false, ""
	}

	// Get the path relative to the mount point for pattern matching
	// req.Path at this point still includes the mount prefix (e.g., "vault-auto/role/terraform/gateway/...")
	// The transparent pattern expects paths relative to the mount (e.g., "role/terraform/gateway/...")
	relativePath := req.Path
	if req.MountPoint != "" {
		relativePath = strings.TrimPrefix(req.Path, req.MountPoint)
	}

	// Check if this path should trigger transparent auth (delegated to the backend).
	// Streaming backends match gateway paths; access backends match access/ paths.
	if !tmp.IsTransparentPath(relativePath) {
		return false, ""
	}

	// Explicit X-Warden-Token means the client wants explicit auth — skip
	// transparent auth entirely so the standard token-validation path runs.
	// Mirrors the same short-circuit on the transparent-ops path at line 743.
	//
	// X-Warden-Agent-Token deliberately does NOT short-circuit here. It carries
	// a JWT or JWT-SVID that still needs a transparent login, and the token
	// store only looks tokens up — it never logs one in — so skipping this path
	// would fail every fresh credential presented on that header. An agent
	// holding an opaque session token has no reason to use it: X-Warden-Token
	// already frees Authorization for the user under extraction rule 1.
	if req.HTTPRequest != nil && req.HTTPRequest.Header.Get(logical.HeaderWardenToken) != "" {
		return false, ""
	}

	// Role resolution precedence (highest wins):
	//   1. X-Warden-Role header
	//   2. Request-encoded role (URL path segment, query param)
	//   3. Provider transparent extractor (SigV4 access key, Basic Auth user)
	//   4. Mount-level default_role
	//
	// Request-encoded role: path segment for streaming backends, query param
	// for access backends. The provider decides what counts.
	authRole := tmp.GetAuthRole(relativePath, req)

	// Provider transparent extractor: SigV4 Authorization header (AWS,
	// Alibaba Cloud), Basic Auth username (Git smart-HTTP), etc.
	if authRole == "" && req.HTTPRequest != nil {
		if ext, ok := backend.(logical.TransparentAuthRoleExtractor); ok {
			authRole = ext.GetAuthRoleFromRequest(req.HTTPRequest)
		}
	}

	// Mount-level default_role.
	if authRole == "" {
		authRole = tmp.GetDefaultAuthRole()
	}

	// X-Warden-Role header overrides everything. HandleRequest also rewrites
	// the role segment of req.Path to match (see applyRoleHeader), so the auth
	// resolver and the streaming backend always agree on which role is in
	// force.
	if req.HTTPRequest != nil {
		if headerRole := req.HTTPRequest.Header.Get("X-Warden-Role"); headerRole != "" {
			authRole = headerRole
		}
	}

	return true, authRole
}

// handleTransparentAuth performs implicit authentication for gateway requests.
// It delegates to performImplicitAuth for credential detection and login.
// The authRole may be empty — the auth method's default_role config provides the fallback.
func (c *Core) handleTransparentAuth(ctx context.Context, req *logical.Request, backend logical.Backend, authRole string) error {
	tmp := backend.(logical.TransparentModeProvider)
	autoAuthPath := tmp.GetAutoAuthPath()
	return c.performImplicitAuth(ctx, req, autoAuthPath, authRole)
}

// captureUserContext resolves the request's secondary (user) principal and
// attaches it to req.User when the provider or namespace configures per-user auth
// (user_auth_path) AND the request actually carries a user credential. It runs
// upfront — before CheckToken, and therefore before the CBP decision — so the
// user is a first-class, already-validated principal by the time authorization
// and minting run. It is IDENTITY-ONLY: it never sets the request's primary token
// entry (never calls req.SetTokenEntry) and never authorizes the request; the
// primary/agent token alone does that.
//
// A missing user credential is NOT an error here: per-user auth being configured
// on a provider does not mean every request through it needs a user principal. An
// absent credential simply leaves req.User nil, and the credential/policy layer
// fails closed only for flows that actually require the user context (a spec with
// assertion_user_claims or a templated secret_path). This keeps user-less requests
// working. What IS fail-closed here is a user credential that is present but
// unusable: invalid/unauthenticable, cross-namespace, or identical to the agent's
// own credential. An unset user_auth_path is a no-op — req.User stays nil and the
// request is byte-identical to before the feature.
// The user credential is supplied by the caller rather than read here: the
// backend's ExtractTokens already decided which wire slot carries the user for
// this provider and this request shape, and the two must not disagree.
func (c *Core) captureUserContext(ctx context.Context, req *logical.Request, userAuthPath, userAuthRole, userCred string) error {
	if userAuthPath == "" {
		return nil // per-user auth not configured — feature off
	}

	if userCred == "" {
		// No user credential presented. Leave req.User nil and let a downstream
		// flow that genuinely needs the user (assertion_user_claims, a templated
		// secret_path) fail closed on its own; a flow that does not is unaffected.
		return nil
	}

	// Fail closed if the user credential is the agent's own token. The two legs
	// now occupy different wire slots, but a client that defensively sets both
	// X-Warden-Token and Authorization to the same JWT would otherwise have the
	// agent double-resolved as its own "user".
	if userCred == req.ClientToken {
		return fmt.Errorf("the user credential must differ from the agent credential")
	}

	// The user credential is a bearer secret riding Authorization (either as a
	// Bearer token or, for git smart-HTTP, in the Basic password slot). Strip the
	// header now that it is captured, so it never proxies to an upstream or lands
	// in an audit header copy — this covers any forwarding path without a Warden
	// strip list. req.User.RawToken retains the value for the RFC 8693
	// subject_token path.
	req.HTTPRequest.Header.Del("Authorization")

	userTE, _, err := c.resolveTransparentIdentity(ctx, req, userAuthPath, userAuthRole, userCred)
	if err != nil {
		return fmt.Errorf("user authentication failed: %w", err)
	}

	// Cross-namespace guard (defense-in-depth): the user must live in the
	// request's namespace. resolveTransparentIdentity routes through the mount in
	// the request namespace, so a mismatch should not arise — fail closed if it does.
	if ns, nsErr := namespace.FromContext(ctx); nsErr == nil && ns != nil && userTE.NamespaceID != ns.ID {
		return fmt.Errorf("user token namespace %q does not match request namespace %q", userTE.NamespaceID, ns.ID)
	}

	req.User = &logical.UserPrincipal{
		TokenEntry: userTE,
		RawToken:   userCred,
	}
	return nil
}

// resolveUserAuthConfig resolves the secondary (user) auth configuration for a
// gateway request from the mount's own config (a backend that implements
// logical.UserAuthConfigProvider). Returns an empty path when per-user auth is
// not configured on this mount.
//
// Deliberately mount-only, unlike auto_auth_path, which also falls back to the
// namespace's custom metadata. Agent identity genuinely is namespace-scoped —
// every workload in a namespace authenticates the same way — but user_auth_path
// marks THIS mount as a protected resource: it decides whether Authorization
// carries the user rather than the agent, and it binds one resource to one
// identity provider and audience. A namespace-wide fallback would opt in every
// mount in the namespace, including ones that never intended to reinterpret
// Authorization, and would force a single user_auth_role's bound_audiences to
// cover every resource at once.
func (c *Core) resolveUserAuthConfig(_ context.Context, backend logical.Backend) (userAuthPath, userAuthRole string) {
	if p, ok := backend.(logical.UserAuthConfigProvider); ok {
		userAuthPath = p.GetUserAuthPath()
		userAuthRole = p.GetUserAuthRole()
	}
	return userAuthPath, userAuthRole
}

// performImplicitAuth performs implicit authentication for the PRIMARY principal
// (the agent) by routing the request's own credential through the auth mount the
// caller's namespace/provider points at. It delegates the credential→TokenEntry
// resolution to resolveTransparentIdentity and then applies the request mutations
// that mark the resolved token as this request's primary principal
// (req.Transparent, req.SetTokenEntry, and the ClientToken assignment). Used by
// both gateway requests and transparent operations.
func (c *Core) performImplicitAuth(ctx context.Context, req *logical.Request, autoAuthPath, authRole string) error {
	// Mark request as implicit auth
	req.Transparent = true

	te, clearClientToken, err := c.resolveTransparentIdentity(ctx, req, autoAuthPath, authRole, "")
	if err != nil {
		return err
	}

	// The X.509-SVID case authenticates via a forwarded/TLS cert; drop any stray
	// non-SVID bearer so the cert-minted token ID becomes ClientToken below.
	if clearClientToken {
		req.ClientToken = ""
	}
	req.SetTokenEntry(te)
	// Ensure ClientToken is set so downstream policy checks (fetchCBPAndTokenEntry)
	// don't short-circuit on the empty-token guard. For JWT transparent auth the
	// JWT string is already in ClientToken, but for cert transparent auth there is
	// no token in the request — only a certificate.
	if req.ClientToken == "" {
		req.ClientToken = te.ID
	}
	return nil
}

// resolveTransparentIdentity turns a credential into a cached-or-freshly-minted
// TokenEntry by routing through the auth mount at autoAuthPath: it resolves the
// mount, selects the registered TransparentTokenType, dispatches on the credential
// format, checks the transparent-token cache, and performs a singleflight login on
// a miss. It is the credential→TokenEntry core shared by performImplicitAuth (the
// primary/agent principal) and the secondary user-principal capture.
//
// It performs NO request mutation — no req.Transparent, no req.ClientToken write,
// no req.SetTokenEntry. Those belong to the primary principal alone and stay in
// performImplicitAuth; leaking any of them here would promote a secondary principal
// to primary. req is read only for the login HTTP context (TLS/forwarded cert),
// client IP, request ID, and cert extraction.
//
// credential, when non-empty, is the bearer token to authenticate — the secondary
// user path passes its header credential here, and the mount must be a bearer
// format (cert/X.509-SVID are rejected: a header can't carry a client cert). When
// empty, the credential is taken from the request the way the primary path expects
// (req.ClientToken for JWT/JWT-SVID, the forwarded/TLS cert for cert/X.509-SVID).
//
// clearClientToken is true only for the X.509-SVID (spiffe-cert) case; it signals
// the primary caller to drop a stray bearer so the cert-minted token ID becomes
// req.ClientToken. It is meaningless for (and ignored by) the secondary path.
//
// Transparent mode precedence rules:
//
//	Outer (handled before this function):
//	  - X-Warden-Token header → explicit auth, implicit auth skipped entirely.
//
//	Auth path (config only, no per-request override — resolved before calling):
//	  - Gateway: provider auto_auth_path config
//	  - Operations: namespace auto_auth_path metadata
//
//	Inside this function:
//	  1. Resolve the mount at autoAuthPath. Reject if no mount is registered.
//	  2. Look up the TransparentTokenType registered for that mount's type
//	     (via the TokenStore registry). Reject if no transparent type serves
//	     this mount type — that means the mount doesn't support implicit auth.
//	  3. Dispatch on the TokenType's CredentialFormat() to extract the
//	     credential the mount expects (TLS client cert vs JWT bearer). Reject
//	     with a specific error if the caller didn't present that credential.
//	  4. Compute a deterministic cache key from (mountAccessor + credential
//	     + role) via the TokenType's LookupValue, look up the cached token,
//	     fall through to an internal login on miss.
//
//	Auth role (first match wins, resolved before calling):
//	  1. X-Warden-Role header
//	  2. Request-encoded role: URL path /role/{name}/gateway/... (streaming
//	     backends) or ?role= query param (access backends)
//	  3. Provider transparent extractor (e.g. SigV4 access key, Basic Auth
//	     username for Git smart-HTTP)
//	  4. Provider default_role config
//	  5. Auth method default_role config (login-time fallback)
//
// Uses singleflight to prevent duplicate token creation when concurrent requests
// arrive with the same credential+authRole combination.
//
// IMPORTANT: The auth role is validated when reusing cached tokens. A token created for
// credential+Role1 cannot be reused for credential+Role2, as they may have different policies.
func (c *Core) resolveTransparentIdentity(ctx context.Context, req *logical.Request, autoAuthPath, authRole, credential string) (te *TokenEntry, clearClientToken bool, err error) {
	// Inject client IP into context so validateIPBinding can read it
	// during cached token lookups. Without this, implicitly-authed tokens
	// bypass IP binding because the context has no client IP.
	if req.ClientIP != "" {
		ctx = context.WithValue(ctx, logical.ClientIPKey, req.ClientIP)
	}

	// A non-empty credential is the secondary (user) path: the mount must be a
	// bearer format, and the credential is used verbatim as the bearer token.
	explicitCred := credential != ""

	// Resolve the auth mount once. mountEntry tells us which TransparentTokenType
	// serves this mount (via the registry) and supplies the stable mount accessor
	// that transparent types fold into their cache key.
	authMountEntry := c.router.MatchingMountEntry(ctx, autoAuthPath)
	if authMountEntry == nil {
		return nil, false, fmt.Errorf("no auth mount registered at %q for implicit auth", autoAuthPath)
	}
	mountAccessor := authMountEntry.Accessor

	// Look up the TransparentTokenType registered for this mount type. If the
	// mount type isn't a transparent auth method (or isn't registered at all),
	// reject the request explicitly rather than silently falling back to
	// credential-format sniffing.
	ttype := c.tokenStore.GetTransparentTokenTypeForAuthMethod(authMountEntry.Type)
	if ttype == nil {
		return nil, false, fmt.Errorf("auth method %q at %q does not support implicit auth", authMountEntry.Type, autoAuthPath)
	}

	var singleflightKey string
	var lookupFunc func() (*TokenEntry, error)
	var loginData map[string]any
	var credKey string // fingerprint or JWT — used for post-login lookup with resolved role

	// Dispatch by the credential's wire-extraction shape. Cases group by what
	// the credential looks like on the wire (cert vs JWT bearer), not by the
	// discovery-level CredentialFormat subtype — JWTRoleTokenType ("jwt") and
	// KubernetesRoleTokenType ("k8s_sa_jwt") both arrive as JWTs in the
	// Authorization header and share the same parse path. The right TokenType
	// is selected upstream via mountEntry.Type, so the cache key remains
	// type-specific even when two formats share an extraction case.
	switch ttype.CredentialFormat() {
	case "cert":
		if explicitCred {
			return nil, false, fmt.Errorf("auth method %q at %q requires a bearer credential, not a TLS client certificate", authMountEntry.Type, autoAuthPath)
		}
		clientCert := extractTransparentClientCert(req)
		if clientCert == nil {
			return nil, false, fmt.Errorf("auth method %q at %q requires a TLS client certificate", authMountEntry.Type, autoAuthPath)
		}
		hash := sha256.Sum256(clientCert.Raw)
		fingerprint := hex.EncodeToString(hash[:])
		sfHash := sha256.Sum256([]byte("cert:" + mountAccessor + ":" + fingerprint + ":" + authRole))
		singleflightKey = hex.EncodeToString(sfHash[:])
		loginData = map[string]any{"role": authRole}
		credKey = fingerprint
		// Authenticate via the client certificate, not any bearer. Signal the
		// primary caller to drop a stray Authorization bearer (ExtractToken falls
		// back to Authorization, so a cert request that also carries a bearer —
		// e.g. a secondary user token on Authorization — would otherwise leave that
		// bearer, not the cert-minted token ID, in ClientToken).
		clearClientToken = true
		lookupFunc = func() (*TokenEntry, error) {
			return c.LookupTransparentTokenWithRole(ctx, ttype, fingerprint, mountAccessor, authRole)
		}

	case "jwt", "k8s_sa_jwt":
		clientToken := credential
		if clientToken == "" {
			clientToken = req.ClientToken
		}
		if !strings.HasPrefix(clientToken, "eyJ") {
			return nil, false, fmt.Errorf("auth method %q at %q requires a JWT bearer token", authMountEntry.Type, autoAuthPath)
		}
		sfHash := sha256.Sum256([]byte("jwt:" + mountAccessor + ":" + clientToken + ":" + authRole))
		singleflightKey = hex.EncodeToString(sfHash[:])
		loginData = map[string]any{"jwt": clientToken, "role": authRole}
		credKey = clientToken
		lookupFunc = func() (*TokenEntry, error) {
			return c.LookupTransparentTokenWithRole(ctx, ttype, clientToken, mountAccessor, authRole)
		}

	case "spiffe":
		// Unified SPIFFE mount: accept either a JWT-SVID (bearer) or an
		// X.509-SVID (TLS/forwarded cert). Prefer an explicitly-presented
		// JWT-SVID over an ambient mesh-forwarded cert — a sidecar makes a
		// forwarded cert present on most requests, so cert-first would shadow
		// the JWT path and mis-attribute a JWT-SVID workload to the cert
		// identity. A JWT-SVID is a bearer JWT whose (unverified) sub is a
		// spiffe:// ID; the mount re-verifies it against the trust-domain bundle.
		clientToken := credential
		if clientToken == "" {
			clientToken = req.ClientToken
		}
		if isSPIFFEJWTSVID(clientToken) {
			sfHash := sha256.Sum256([]byte("spiffe-jwt:" + mountAccessor + ":" + clientToken + ":" + authRole))
			singleflightKey = hex.EncodeToString(sfHash[:])
			loginData = map[string]any{"jwt": clientToken, "role": authRole}
			credKey = clientToken
			lookupFunc = func() (*TokenEntry, error) {
				return c.LookupTransparentTokenWithRole(ctx, ttype, clientToken, mountAccessor, authRole)
			}
		} else if explicitCred {
			// The secondary (user) path is bearer-only; an X.509-SVID can't ride a
			// header, so a non-SVID credential here is a misconfigured user mount.
			return nil, false, fmt.Errorf("auth method %q at %q requires a JWT-SVID bearer credential", authMountEntry.Type, autoAuthPath)
		} else if clientCert := extractTransparentClientCert(req); clientCert != nil {
			hash := sha256.Sum256(clientCert.Raw)
			fingerprint := hex.EncodeToString(hash[:])
			sfHash := sha256.Sum256([]byte("spiffe-cert:" + mountAccessor + ":" + fingerprint + ":" + authRole))
			singleflightKey = hex.EncodeToString(sfHash[:])
			loginData = map[string]any{"role": authRole}
			credKey = fingerprint
			// Authenticate via the X.509-SVID, not any bearer. Signal the primary
			// caller to clear a stray non-SVID bearer so the cert-minted token ID
			// becomes ClientToken (this function performs no request mutation).
			clearClientToken = true
			lookupFunc = func() (*TokenEntry, error) {
				return c.LookupTransparentTokenWithRole(ctx, ttype, fingerprint, mountAccessor, authRole)
			}
		} else {
			return nil, false, fmt.Errorf("auth method %q at %q requires an X.509-SVID (TLS/forwarded cert) or a JWT-SVID bearer token", authMountEntry.Type, autoAuthPath)
		}

	default:
		return nil, false, fmt.Errorf("auth method %q has unsupported credential format %q for implicit auth", authMountEntry.Type, ttype.CredentialFormat())
	}

	// Step 1: Try cached lookup
	// Note: cached tokens are returned without re-checking certificate revocation.
	// This is an accepted design trade-off — revocation is a best-effort signal and
	// the token TTL (default 1h) bounds the exposure window. Explicit login requests
	// always perform full revocation checks. To reduce exposure for revoked certs,
	// configure a shorter token_ttl on cert roles.
	te, err = lookupFunc()
	if err == nil && te != nil {
		return te, clearClientToken, nil
	}

	// IP binding violation means the token exists but the client IP doesn't match.
	// Return the error immediately — don't fall through and create a new token.
	if err == ErrOriginViolation {
		return nil, false, err
	}

	// Step 2: Token not found — perform implicit auth with singleflight
	result, err, shared := c.transparentAuthGroup.Do(singleflightKey, func() (interface{}, error) {
		// Double-check: another goroutine may have just created the token
		checkTE, lookupErr := lookupFunc()
		if lookupErr == nil && checkTE != nil {
			return checkTE, nil
		}
		// Same as above: IP binding violation should not trigger re-login
		if lookupErr == ErrOriginViolation {
			return nil, lookupErr
		}

		// Build login request to the auto-auth path (e.g., auth/jwt/login or auth/cert/login)
		loginPath := strings.TrimSuffix(autoAuthPath, "/") + "/login"
		loginReq := &logical.Request{
			Operation:   logical.UpdateOperation,
			Path:        loginPath,
			HTTPRequest: req.HTTPRequest, // Carries TLS info and forwarded cert context
			Data:        loginData,
			ClientIP:    req.ClientIP,
			RequestID:   req.RequestID,
		}

		// Perform the login request
		loginResp, _, loginErr := c.handleLoginRequest(ctx, loginReq, true)
		if loginErr != nil {
			return nil, loginErr
		}

		if loginResp != nil && loginResp.Err != nil {
			return nil, loginResp.Err
		}

		if loginResp == nil || loginResp.Auth == nil {
			return nil, fmt.Errorf("implicit auth returned no auth data")
		}

		// Lookup the newly created token using the resolved role from the login response.
		// This handles default_role fallback: the original role may be empty, but the
		// auth method resolves it to default_role. The token is stored with the resolved role.
		resolvedRole := loginResp.Auth.RoleName
		var newTE *TokenEntry
		var postErr error
		newTE, postErr = c.LookupTransparentTokenWithRole(ctx, ttype, credKey, mountAccessor, resolvedRole)
		if postErr != nil {
			return nil, fmt.Errorf("failed to lookup created token: %w", postErr)
		}

		return newTE, nil
	})

	if err != nil {
		c.transparentAuthGroup.Forget(singleflightKey)
		return nil, false, err
	}

	te = result.(*TokenEntry)
	_ = shared

	return te, clearClientToken, nil
}

// isSPIFFEJWTSVID reports whether token is a JWT whose unverified subject is a
// SPIFFE ID (a JWT-SVID). The spiffe transparent-auth dispatch uses it to prefer
// an explicitly-presented JWT-SVID over an ambient mesh-forwarded cert. The
// signature is NOT verified here — the mount re-verifies the JWT-SVID against
// the trust-domain bundle at login.
func isSPIFFEJWTSVID(token string) bool {
	if !strings.HasPrefix(token, "eyJ") {
		return false
	}
	claims, err := helper.ParseJWTClaimsUnverified(token)
	if err != nil {
		return false
	}
	sub, _ := claims["sub"].(string)
	return strings.HasPrefix(sub, "spiffe://")
}

// extractTransparentClientCert extracts the client certificate from a request.
// The cert forwarding middleware stores it in the request context after
// extracting it from either a forwarding header (X-SSL-Client-Cert or
// X-Forwarded-Client-Cert from a trusted proxy) or the TLS connection
// state (r.TLS.PeerCertificates for direct mTLS / LB passthrough).
// On cluster-forwarded requests (standby → leader), the header is
// re-forwarded and re-parsed, so ForwardedClientCert works correctly
// for all paths.
func extractTransparentClientCert(req *logical.Request) *x509.Certificate {
	if req.HTTPRequest == nil {
		return nil
	}

	return listener.ForwardedClientCert(req.HTTPRequest.Context())
}
