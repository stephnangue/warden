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
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-multierror"
	"github.com/openbao/openbao/sdk/v2/helper/pathmanager"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	spiffelib "github.com/stephnangue/warden/auth/spiffe"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/credential/drivers"
	"github.com/stephnangue/warden/credential/profiles"
	"github.com/stephnangue/warden/helper/flight"
	"github.com/stephnangue/warden/helper/selector"
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
		cbp, te, err = c.fetchCBPAndTokenEntry(ctx, req, unauth)
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
	// Carry the MCP decision (when an MCP rule-set was consulted)
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
			// when the denial came from an MCP gate, so the HTTP
			// layer can render the OAuth-shaped 403 body. Unwrap()
			// returns ErrPermissionDenied so every existing
			// errors.Is(err, ErrPermissionDenied) call site keeps
			// working unchanged.
			if auth.MCPDecision != nil && auth.MCPDecision.Decision == "deny" {
				// A header mismatch is a protocol-level disagreement, not an
				// authorization failure, and the HTTP layer renders it as
				// one. It must be split out here: both arrive as a deny
				// MCPDecision, and the generic wrapper below would send it
				// out as the OAuth-shaped 403 — which a dual-era client
				// reads as "not permitted" and answers by downgrading to
				// initialize, rather than by fixing its headers.
				if auth.MCPDecision.RuleType == mcpRuleTypeHeaderMismatch {
					retErr = multierror.Append(retErr, mcpHeaderMismatchError(req, auth.MCPDecision))
				} else {
					retErr = multierror.Append(retErr, &ErrMCPPolicyDenied{Decision: auth.MCPDecision})
				}
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

// fetchCBPAndTokenEntry resolves the request's identity in three steps: the
// token entry (lookupTokenEntry), the role it runs under (resolveRoleGrant,
// which projects a per-request role onto the entry), then the CBP of the
// entry's policies (buildCBP). Verdicts stay in performPolicyChecks.
//
// An unauthenticated check (a login) grants no role: no verdict is rendered
// on it, so none is resolved, and its audit entry records none
// (withholdRoleGrant).
func (c *Core) fetchCBPAndTokenEntry(ctx context.Context, req *logical.Request, unauth bool) (*CBP, *logical.TokenEntry, error) {
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

	te, err := c.lookupTokenEntry(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	if unauth {
		withholdRoleGrant(req, te)
	} else {
		c.resolveRoleGrant(req, te, time.Now())
	}

	// A refused role grant keeps no policies so that the CBP refuses it, and
	// that holds for the built-ins too: attached to it, they would authorize a
	// refused grant wherever they grant.
	rg := req.RoleGrant()
	withBuiltins := rg == nil || rg.Granted()

	cbp, err := c.buildCBP(ctx, te, withBuiltins)
	if err != nil {
		return nil, nil, err
	}
	return cbp, te, nil
}

// lookupTokenEntry returns the request's token entry: the one already set on
// req (implicit auth sets it), or the one req.ClientToken names, which it then
// sets. Either way it is this request's own copy.
func (c *Core) lookupTokenEntry(ctx context.Context, req *logical.Request) (*logical.TokenEntry, error) {
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
				return nil, sdklogical.ErrPermissionDenied
			}
			c.logger.Error("failed to lookup token", logger.Err(err))
			return nil, ErrInternalError
		}
		req.SetTokenEntry(te)
	default:
		te = req.TokenEntry()
	}

	// Ensure the token is valid
	if te == nil {
		return nil, sdklogical.ErrPermissionDenied
	}
	return te, nil
}

// buildCBP compiles the CBP of te's policies, in te's namespace, together with
// that namespace's built-in policies when withBuiltins is set, unless te is a
// root token.
//
// This is the one place the built-ins are attached. A reserved name on the
// token is dropped first: a built-in it names is attached anyway, by type, and
// a policy left under another reserved name is given to no request. The names
// are gathered into a slice of their own, since te.Policies may be a role's
// shared slice. Root is recognised by its canonical name, as the policy store
// resolves it.
func (c *Core) buildCBP(ctx context.Context, te *logical.TokenEntry, withBuiltins bool) (*CBP, error) {
	names := make([]string, 0, len(te.Policies))
	isRoot := false
	for _, name := range te.Policies {
		canonical, ok := logical.CanonicalPolicyName(name)
		if ok && isReservedPolicyName(canonical) {
			continue
		}
		if ok && canonical == "root" {
			isRoot = true
		}
		names = append(names, name)
	}
	policyNames := map[string][]string{te.NamespaceID: names}

	tokenNS, err := c.NamespaceByID(ctx, te.NamespaceID)
	if err != nil {
		c.logger.Error("failed to fetch token namespace", logger.Err(err))
		return nil, ErrInternalError
	}

	if tokenNS == nil {
		c.logger.Error("failed to fetch token namespace", logger.Err(namespace.ErrNoNamespace))
		return nil, ErrInternalError
	}

	tokenCtx := namespace.ContextWithNamespace(ctx, tokenNS)

	// Construct the corresponding CBP object. CBP construction should be
	// performed on the token's namespace.
	if c.policyStore == nil {
		c.logger.Error("policy store is unavailable")
		return nil, ErrInternalError
	}

	// Root is the whole grant on its own and admits no other policy beside it.
	// The built-ins are gathered into a fixed buffer so the slice need not
	// reach the heap.
	var buf [2]*Policy
	builtins := buf[:0]
	if withBuiltins && !isRoot {
		builtins, err = c.policyStore.appendDefaultPolicies(tokenCtx, builtins)
		if err != nil {
			c.logger.Error("failed to fetch built-in policies", logger.Err(err))
			return nil, ErrInternalError
		}
	}
	cbp, err := c.policyStore.CBP(tokenCtx, policyNames, builtins...)
	if err != nil {
		c.logger.Error("failed to construct CBP", logger.Err(err))
		return nil, ErrInternalError
	}
	return cbp, nil
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

		// The role is spliced into the path policies are matched against,
		// after the HTTP layer checked that path, so it must be a role name
		// and nothing that adds or walks a segment.
		if headerRole != "" && !validSysName(headerRole) {
			return logical.ErrorResponse(logical.ErrBadRequestf("invalid X-Warden-Role %.64q: %s", headerRole, sysNameRule)), nil
		}

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
// and stripped. Empty path segments and bare "." and ".." segments are
// rejected: the result is the path policies are matched against.
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
		if seg == "." || seg == ".." {
			return "", fmt.Errorf("X-Warden-Provider value contains a dot segment")
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
	// Routing rewrites req.Path; the gateway failure hook needs the original.
	routePath := req.Path

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

	// A gateway request Warden failed itself is answered in the owning
	// provider's native wire format when the provider renders one. Done before
	// the audit so the audit records what the client actually receives.
	resp, err = c.renderGatewayFailure(ctx, req, routePath, resp, err)

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
	// this request's own implicit auth extracted, and the HTTP request it carries
	// belongs to the gateway call that triggered the login. Parsing here would merge
	// that caller's query params and body keys into the resolved map — a body of
	// {"jwt":"other"} would pick the credential the login admits, through a channel
	// that never reaches req.Path and so is invisible to both policy and the audit
	// log.
	if !isInternalLogin {
		if err := c.parseRequestBody(req); err != nil {
			return logical.ErrorResponse(err), nil, nil
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

		// Build the error response
		var resp *logical.Response
		if ctErr == ErrInternalError {
			resp = nil
		} else {
			resp = logical.ErrorResponse(logical.ErrInternal(ctErr.Error()))
		}

		// No response audit here, for the same reason as the token-check denial
		// below: handleCancelableRequest audits the response of every request it
		// handles, so auditing here too would record this one twice.
		//
		// The other caller — the transparent-auth internal login — audits no
		// response at all, so this branch would have been that sub-request's only
		// response entry. Removing it matches how a *successful* internal login
		// already behaves (a request entry, no response entry), so the asymmetry
		// predates this and is not introduced by dropping the call.
		//
		// This branch is unreachable today in any case: CheckToken is called here
		// with unauth=true, which swallows every token/CBP fetch error and skips
		// the policy gate entirely, and its remaining exits need a backend that
		// either declares an ExistenceCheck (none does) or lists one path as both
		// Root and Unauthenticated (none does). It is kept rather than deleted so
		// that if a future backend makes it live, it fails as one audit entry
		// rather than silently as two.
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
			return logical.ErrorResponse(logical.ErrBadRequest("explicit login is not supported for transparent auth methods; clients authenticate implicitly via gateway requests")), nil, nil
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
	if err := logical.ValidateAssignablePolicies(auth.Policies); err != nil {
		return logical.ErrorResponse(logical.ErrForbidden(err.Error())), sdklogical.ErrInvalidRequest
	}

	// req.MountAccessor is populated by handleLoginRequest from the routed
	// mount entry. Carry it through so transparent token types can fold it
	// into their cache key (prevents cross-mount cache contamination when
	// two mounts of the same auth type are presented the same credential).
	var mountAccessor string
	if req != nil {
		mountAccessor = req.MountAccessor
	}

	if auth.Admission != nil {
		c.setAdmissionMountPath(ctx, req, auth.Admission)
	}

	// A login is an admission: the token carries no role and no credential
	// spec, which are granted per request.
	now := time.Now()
	authData := logical.AuthData{
		PrincipalID:   auth.PrincipalID,
		ExpireAt:      now.Add(auth.TokenTTL),
		Policies:      auth.Policies,
		ClientIP:      auth.ClientIP,
		TokenValue:    auth.ClientToken,
		MountAccessor: mountAccessor,
		Actors:        auth.Actors,
		Metadata:      auth.Metadata,
		Admission:     auth.Admission,
	}

	// The issued entry may not be the one authData describes: a transparent
	// token already cached for this credential and mount is returned instead,
	// with its own admission. Anything read after this point is read from
	// tokenValue, never from auth.
	tokenValue, err := c.tokenStore.GenerateToken(ctx, auth.TokenType, &authData)

	if err != nil {
		// Named fields only: authData carries the login credential itself in
		// TokenValue (the caller's JWT, or a certificate fingerprint) and the
		// login claims in Metadata, neither of which belongs in a log.
		fields := []logger.TypedField{
			logger.Err(err),
			logger.String("token_type", auth.TokenType),
			logger.String("principal_id", authData.PrincipalID),
			logger.String("mount_accessor", authData.MountAccessor),
		}
		if ns, nsErr := namespace.FromContext(ctx); nsErr == nil {
			fields = append(fields, logger.String("namespace", ns.Path))
		}
		c.logger.Error("Failed to generate token", fields...)
		return logical.ErrorResponse(logical.ErrInternal("failed to generate token")), ErrInternalError
	}

	data := map[string]any{
		"token_type":     tokenValue.Type,
		"expire_at":      tokenValue.ExpireAt,
		"bound_ip":       tokenValue.CreatedByIP,
		"token_id":       tokenValue.ID,
		"token_assessor": tokenValue.Accessor,
		"namespace":      tokenValue.NamespacePath,
		"principal_id":   tokenValue.PrincipalID,
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

// setAdmissionMountPath names the admitting mount on adm relative to the
// namespace, the form a selector pins: req.MountPoint carries the namespace
// prefix, which is cut off. Only this function sets MountPath, once per login,
// before the token store shares the admission; one that arrives already set is
// kept. When the mount cannot be named (no request, no namespace, a mount point
// outside the namespace) MountPath stays empty and the "mount" fact is absent,
// so no rule pinning a mount matches.
func (c *Core) setAdmissionMountPath(ctx context.Context, req *logical.Request, adm *logical.Admission) {
	if adm.MountPath != "" {
		c.logger.Warn("admission already names its mount; keeping it",
			logger.String("mount_path", adm.MountPath))
		return
	}
	var mountPoint string
	if req != nil {
		mountPoint = req.MountPoint
	}
	ns, err := namespace.FromContext(ctx)
	if err != nil || ns == nil {
		c.logger.Warn("admission mount left unnamed: no namespace in context",
			logger.String("mount_point", mountPoint))
		return
	}
	rel, ok := strings.CutPrefix(mountPoint, ns.Path)
	if !ok || rel == "" {
		c.logger.Warn("admission mount left unnamed: mount point is not inside the namespace",
			logger.String("mount_point", mountPoint),
			logger.String("namespace", ns.Path))
		return
	}
	adm.MountPath = rel
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

	// Whether this mount is a protected resource — i.e. whether a user
	// credential can be presented at all. Resolved inside the streaming branch
	// below, but declared here so the policy-denial path can read it: a deny
	// that a user might remedy is answered with a challenge only when there is
	// somewhere to send the client.
	var userLegMount bool

	if !isStreaming {
		if err := c.parseRequestBody(req); err != nil {
			return logical.ErrorResponse(err), nil, nil
		}

		// A provider's transparent surface is not only its streaming gateway:
		// an access backend serves its access/ paths as ordinary requests. When
		// the provider authenticates this path implicitly, the agent credential
		// is extracted and logged in exactly as on a gateway path, the provider's
		// own auto_auth_path taking precedence over the namespace's below.
		provider, authRole, providerAuth := c.providerTransparentSurface(ctx, req, entry)
		if providerAuth {
			req.ClientToken, _ = provider.ExtractTokens(req.HTTPRequest, false)
			if failure := c.authenticateImplicitly(ctx, req, provider, authRole, noRoleSelectedAccess); failure != nil {
				return failure, nil, nil
			}
		} else {
			req.ClientToken = extractToken(req.HTTPRequest)
		}

		// Transparent operations: implicit auth on non-gateway endpoints.
		// Triggered when there's no explicit X-Warden-Token but an auth path
		// is configured on the namespace. The Authorization: Bearer value is
		// treated as a JWT credential, not a Warden token.
		// Role precedence: ?role= query param > X-Warden-Role header; an empty
		// ?role= selects nothing, so it leaves the header in force. There is
		// no provider here, so no default_role: a request selecting neither is
		// refused before its credential is admitted.
		if !providerAuth && req.HTTPRequest != nil && req.HTTPRequest.Header.Get("X-Warden-Token") == "" {
			var authPath string
			if ns, _ := namespace.FromContext(ctx); ns != nil {
				authPath = ns.CustomMetadata["auto_auth_path"]
			}
			if authPath != "" {
				var authRole string
				if role, _ := req.Data["role"].(string); role != "" {
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
					return implicitAuthFailure(err, noRoleSelectedOperations), nil, nil
				}
			}
		}
	} else {
		req.Streamed = true

		// Shed the listener's write deadline for the whole of this request. It
		// is armed when request headers are read and absolute from that
		// moment, so on a streaming path it caps the proxied call itself: a
		// response over it dies with a bare EOF and no status, and a stream is
		// truncated mid-flight. The mount's own timeout is the real ceiling
		// for this traffic. Control-plane requests take the branch above and
		// keep their caps.
		if err := logical.ClearStreamWriteDeadline(req.ResponseWriter); err != nil {
			c.logger.Warn("could not clear connection write deadline for streaming request",
				logger.Err(err),
				logger.String("path", req.Path),
			)
		}

		// The read deadline gets a window rather than a clear, because the
		// body buffering below runs BEFORE the caller is authenticated: the
		// stream-body parser and the MCP extractor both read the body, and
		// the mount timeout that would otherwise bound them is not armed
		// until the backend handler runs. Clearing it here would let an
		// unauthenticated client dribble a body forever, holding a goroutine
		// and a buffer with nothing to push back. The window is generous
		// enough for a legitimately slow upload of a capped body and is
		// removed as soon as the body is in hand.
		//
		// This is also why the clear cannot live in the providers' gateway
		// handlers, where the plan first put it: by the time one runs, the
		// body has already been read under whatever deadline was in force.
		c.setStreamReadWindow(req, time.Now().Add(streamBodyBufferTimeout))

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
			if err := c.parseRequestBodyLimit(req, streamBodyParseLimit(matchingBackend, req.HTTPRequest)); err != nil {
				return logical.ErrorResponse(err), nil, nil
			}
		}

		// MCP body-authoritative policy enforcement: when the routed
		// backend opts into logical.MCPPolicyEnforced, buffer the
		// request body and strict-parse it into a descriptor before
		// CheckToken runs. The extractor restores the body so the
		// downstream proxy reads it unchanged. Non-MCP backends fail
		// the type assertion and skip the extractor entirely.
		c.extractMCPDescriptor(ctx, req, matchingBackend)

		// The body is in hand, so the window closes: from here the response
		// may stream for as long as the mount allows, and an armed read
		// deadline would tear it down even while idle — net/http reads the
		// connection in the background once the body is drained and cancels
		// the request context when that read fails.
		c.setStreamReadWindow(req, time.Time{})

		// Resolve the secondary (user) auth config once, before extraction:
		// whether this mount is a protected resource decides how the extractor
		// reads Authorization. On a mount with no effective user_auth_path the
		// rule collapses to the pre-0.20 behaviour and userCred stays empty.
		userAuthPath, userAuthRefusal := c.resolveUserAuthConfig(ctx, matchingBackend)
		userLeg := userAuthPath != ""
		userLegMount = userLeg

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
				if failure := c.authenticateImplicitly(ctx, req, matchingBackend, role, noRoleSelectedGateway); failure != nil {
					return failure, nil, nil
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
			if err := c.captureUserContext(ctx, req, userAuthPath, userAuthRefusal, userCred); err != nil {
				c.logger.Warn("secondary user authentication failed",
					logger.Err(err),
					logger.String("path", req.Path),
					logger.String("request_id", req.RequestID),
				)
				return c.userCaptureFailure(ctx, req, err), nil, nil
			}
		}
	}

	var auth *logical.Auth
	var te *logical.TokenEntry

	// An unauthenticated streaming path skips CheckToken, and with it every
	// policy gate — including the MCP contract. A JSON-RPC body reaching that
	// branch would be proxied having answered to nothing, which is exactly the
	// invariant the absence deny exists to hold.
	//
	// No provider produces this combination today. Unreachability rests on the
	// spec hooks rather than the interfaces: httpproxy's shared backend
	// implements both TransparentModeProvider and MCPPolicyEnforced, and only
	// github and gitlab set IsUnauthenticatedRequest while only mcp sets
	// ShouldEnforceMCPPolicy. One future spec setting both makes this live, so
	// it fails closed and loudly rather than passing traffic silently.
	if req.StreamUnauthenticated && mcpDescriptorPopulated(req) {
		// Logged because this branch firing means one specific thing — a
		// provider spec now sets both IsUnauthenticatedRequest and
		// ShouldEnforceMCPPolicy — and the operator should learn it here
		// rather than from a client reporting refusals. Audit is skipped for
		// this path by design (no principal exists to attribute it to), so the
		// operational log is the only signal.
		c.logger.Warn("refusing MCP request on an unauthenticated streaming path",
			logger.String("path", req.Path))
		return logical.ErrorResponse(logical.ErrForbidden(
			"MCP requests cannot use unauthenticated streaming paths")), nil, nil
	}

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

			// A policy denied because no user rode a request that could have
			// carried one. 403 is the wrong answer: nothing in a real client
			// stack acts on it, so the caller concludes it is forbidden when one
			// OAuth round trip away it might succeed. Answer 401 and name where
			// to authenticate, exactly as the credential layer already does when
			// a spec requires a user (see exchangeInputError).
			//
			// Swapping resp here rather than at the return is what keeps the
			// audit honest: handleCancelableRequest audits whatever this returns,
			// so the logged status is the 401 the client actually received. The
			// request entry still records the policy denial and its
			// ConditionResult, and user_absent on that record is what explains
			// why a denial went out as an invitation to authenticate.
			if challenge := c.userChallengeForDeny(ctx, req, auth, userLegMount); challenge != nil {
				resp = challenge
				retErr = nil
			}

			// No response audit here. handleCancelableRequest audits the response
			// of every request once this returns, so auditing again would record
			// a denial twice — and anything counting audit events (denial rate
			// limits, alerting, compliance tallies) would see two rejections
			// where one occurred.
			//
			// The caller's entry carries the same response, auth and token entry
			// (it re-reads req.TokenEntry(), which was set before any denial can
			// occur). For a permission denial its error IS this ctErr. For the
			// default class above — neither internal nor permission-denied —
			// retErr is a generic invalid-request instead, so that entry's Error
			// field is less specific than this one was; the exact ctErr is still
			// recorded on the request entry below and in the audited response
			// body, so nothing leaves the audit record.
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
			c.attachUpstreamUserChallenge(ctx, req, errResp, err)
			return errResp, auth, nil
		}
	}

	// Route the request
	resp, routeErr := c.doRouting(ctx, req)

	// A provider's config read also says, ahead of time, when its user leg
	// would refuse every user credential, or an auth path names a mount of the
	// wrong kind: only core sees the auth mounts and the protected-resource
	// configuration that decide it.
	if entry != nil && entry.Class == mountClassProvider && !req.Streamed &&
		req.Operation == logical.ReadOperation && req.Path == "config" && resp != nil && resp.Err == nil {
		if warnings := c.providerConfigWarnings(ctx, entry); len(warnings) > 0 {
			if resp.Data == nil {
				resp.Data = map[string]any{}
			}
			appendWarnings(resp.Data, warnings...)
		}
	}

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
		if err := c.mintSpecForRequest(ctx, req, te, ad.CredentialSpec); err != nil {
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

// streamBodyBufferTimeout bounds the pre-authentication body buffering on a
// streaming path — the stream-body parser and the MCP extractor. It is the
// only thing standing between an unauthenticated client and a goroutine plus
// a max_body_size buffer held open indefinitely, since the mount timeout is
// not armed until the backend handler runs. Generous enough that a capped
// body on a slow link finishes comfortably.
const streamBodyBufferTimeout = 60 * time.Second

// setStreamReadWindow moves the connection read deadline for a streaming
// request; the zero time removes it. Failure is logged, not fatal: the
// request is still correct without the adjustment, it is merely bounded by
// whatever the listener armed.
func (c *Core) setStreamReadWindow(req *logical.Request, deadline time.Time) {
	if err := logical.SetStreamReadDeadline(req.ResponseWriter, deadline); err != nil {
		c.logger.Warn("could not adjust connection read deadline for streaming request",
			logger.Err(err),
			logger.String("path", req.Path),
		)
	}
}

// isStreamingRequest checks if the request path is a streaming path
func (c *Core) isStreamingRequest(ctx context.Context, path string) bool {
	return c.router.StreamingPath(ctx, path)
}

// parseRequestBody parses query params and JSON body into req.Data, buffering at
// most maxRequestBodySize of the body.
func (c *Core) parseRequestBody(req *logical.Request) error {
	return c.parseRequestBodyLimit(req, maxRequestBodySize)
}

// streamBodyParseLimit returns how much of a streamed request body core may buffer
// to parse it for policy: the backend's own cap when it reports one, so core never
// holds more than the backend would forward, else maxRequestBodySize.
func streamBodyParseLimit(backend logical.Backend, r *http.Request) int64 {
	if l, ok := backend.(logical.StreamBodyLimiter); ok {
		if limit := l.StreamBodyLimit(r); limit > 0 {
			return limit
		}
	}
	return maxRequestBodySize
}

// parseRequestBodyLimit is parseRequestBody with the body cap supplied.
func (c *Core) parseRequestBodyLimit(req *logical.Request, limit int64) error {
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
	return c.parseBody(req, limit)
}

// parseBody dispatches to the appropriate body parser based on Content-Type.
// Supports JSON (see isJSONMediaType) and application/x-www-form-urlencoded.
// Unknown content types are silently skipped (body left untouched).
func (c *Core) parseBody(req *logical.Request, limit int64) error {
	mediaType := bodyMediaType(req.HTTPRequest.Header.Get("Content-Type"))

	switch {
	case isJSONMediaType(mediaType):
		return c.parseJSONBody(req, limit)
	case mediaType == "application/x-www-form-urlencoded":
		return c.parseFormBody(req, limit)
	default:
		return nil
	}
}

// bodyMediaType returns the media type of a Content-Type value: lowercased, with
// its parameters dropped, and "" for an absent header. Media types are
// case-insensitive (RFC 9110 §8.3.1). A value mime.ParseMediaType rejects (a
// malformed parameter, say) still yields the part before ';', so a sloppy
// parameter cannot turn a JSON body into one policy never sees.
func bodyMediaType(contentType string) string {
	if strings.TrimSpace(contentType) == "" {
		return ""
	}
	if mediaType, _, err := mime.ParseMediaType(contentType); err == nil {
		return mediaType
	}
	mediaType, _, _ := strings.Cut(contentType, ";")
	return strings.ToLower(strings.TrimSpace(mediaType))
}

// isJSONMediaType reports whether a body labelled mediaType is parsed as JSON for
// policy. That is any spelling an upstream may decode as JSON, so a caller cannot
// relabel a body to slip it past a condition: application/json, text/json, any
// structured-syntax +json type (RFC 6839, e.g. application/vnd.api+json or
// application/merge-patch+json), and an absent type, which core has always read as
// JSON. A body that then fails to parse is refused.
func isJSONMediaType(mediaType string) bool {
	return mediaType == "" ||
		mediaType == "application/json" ||
		mediaType == "text/json" ||
		strings.HasSuffix(mediaType, "+json")
}

// readAndRestoreBody buffers the request body under the size cap and puts it back, so
// everything downstream — the proxy to the upstream, the MCP extractor, audit — still
// reads it whole.
//
// Its errors are coded. A body Warden cannot buffer or parse is the caller's problem,
// and an uncoded error reaches the wire as a 500 that blames Warden for it.
func (c *Core) readAndRestoreBody(req *logical.Request, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(req.HTTPRequest.Body, limit+1))
	if err != nil {
		c.logger.Debug("failed to read request body",
			logger.Err(err),
			logger.String("path", req.Path),
		)
		return nil, logical.ErrBadRequest("failed to read request body")
	}
	req.HTTPRequest.Body.Close()

	if int64(len(body)) > limit {
		return nil, logical.ErrRequestEntityTooLargef("request body exceeds maximum size of %d bytes", limit)
	}

	// Restore body for potential re-reading (audit, streaming, etc.)
	req.HTTPRequest.Body = io.NopCloser(bytes.NewReader(body))

	return body, nil
}

// parseJSONBody parses the JSON body of the request into req.Data.
//
// Only a top-level object contributes fields. A top-level array or scalar is
// legitimate JSON — it is the request shape for batch, bulk and series endpoints, and
// for JSON-RPC batches — so it parses successfully and contributes nothing: req.Data
// keeps the query params alone, and the body reaches the upstream as the bytes
// restored above. Decoding straight into req.Data would instead fail those requests
// against the map's shape, before they were even authorised.
func (c *Core) parseJSONBody(req *logical.Request, limit int64) error {
	if req.HTTPRequest.Body == nil {
		return nil
	}

	if !isJSONMediaType(bodyMediaType(req.HTTPRequest.Header.Get("Content-Type"))) {
		return nil // Not JSON, skip
	}

	body, err := c.readAndRestoreBody(req, limit)
	if err != nil {
		return err
	}

	if len(body) == 0 {
		return nil
	}

	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		// The decoder's message names Go types. That is a diagnostic, not an API
		// contract — keep it in the log and answer with a stable one.
		c.logger.Debug("request body is not valid JSON",
			logger.Err(err),
			logger.String("path", req.Path),
		)
		return logical.ErrBadRequest("request body is not valid JSON")
	}

	obj, ok := root.(map[string]any)
	if !ok {
		return nil
	}
	for k, v := range obj {
		req.Data[k] = v
	}

	return nil
}

// parseFormBody parses application/x-www-form-urlencoded body into req.Data.
// Like parseJSONBody, it reads the body with a size limit and restores it for re-reading.
func (c *Core) parseFormBody(req *logical.Request, limit int64) error {
	if req.HTTPRequest.Body == nil {
		return nil
	}

	body, err := c.readAndRestoreBody(req, limit)
	if err != nil {
		return err
	}

	if len(body) == 0 {
		return nil
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		c.logger.Debug("request body is not valid form data",
			logger.Err(err),
			logger.String("path", req.Path),
		)
		return logical.ErrBadRequest("request body is not valid form data")
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

// projectAgentClaims builds the primary principal's {{agent.<claim>}} template map
// for a subject source that mints no assertion, and so has no projection to borrow.
//
// It mirrors what buildAssertionSetup composes for the warden_identity path — the
// allow-listed metadata plus an authoritative "sub" — so one spec templates the same
// way whichever source it uses. Absent keys are skipped rather than rejected, matching
// projectAssertionMetadata: a claim that is named but missing fails at template time in
// the driver, and only when a path actually references it.
func projectAgentClaims(te *logical.TokenEntry, keys []string) (map[string]string, error) {
	projected, _, err := projectAssertionMetadata(te.Metadata, keys)
	if err != nil {
		return nil, err
	}
	return agentTemplateClaims(projected, te.PrincipalID), nil
}

// agentTemplateClaims composes the {{agent.<claim>}} map from an allow-listed
// metadata projection. Both subject sources compose through here so they cannot
// drift apart. The identity sub is authoritative and set last: a metadata key
// literally named "sub" still reaches the assertion, but never the template.
func agentTemplateClaims(projected map[string]string, principalID string) map[string]string {
	claims := make(map[string]string, len(projected)+1)
	for k, v := range projected {
		claims[k] = v
	}
	claims["sub"] = principalID
	return claims
}

// projectUserClaims selects the operator-allowlisted keys from the secondary
// (user) principal's metadata for the assertion's user level and for per-user
// secret_path templating. Unlike projectAssertionMetadata it FAILS CLOSED on an
// absent key: the user's claims scope a security-sensitive downstream path (a
// templated policy / a per-user secret path), so a named-but-missing claim must
// deny rather than silently widen the scope. Returns the projected map, which is
// empty-key → nil, and its JSON encoding, the fingerprint the credential cache
// keys it by ("" when nothing is projected).
func projectUserClaims(md map[string]string, keys []string) (map[string]string, string, error) {
	if len(keys) == 0 {
		return nil, "", nil
	}
	projected := make(map[string]string, len(keys))
	for _, k := range keys {
		v, ok := md[k]
		if !ok {
			return nil, "", fmt.Errorf("assertion_user_claims names %q but the user token has no such claim", k)
		}
		projected[k] = v
	}
	encoded, err := json.Marshal(projected)
	if err != nil {
		return nil, "", fmt.Errorf("marshal user claims: %w", err)
	}
	if len(encoded) > maxAssertionMetadataBytes {
		return nil, "", fmt.Errorf("user claims exceed %d bytes", maxAssertionMetadataBytes)
	}
	return projected, string(encoded), nil
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
		SubjectTokenType: spec.Config.Get(credential.ConfigSubjectTokenType),
		ActorTokenType:   spec.Config.Get(credential.ConfigActorTokenType),
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
	// assertion's user level and per-user secret_path templating. Read from the
	// request — the same object the chaining closure captures, so it is present for a
	// chained secret-spec too.
	var userTE *logical.TokenEntry
	if req.User != nil {
		userTE = req.User.TokenEntry
	}

	switch spec.Config.Get(credential.ConfigSubjectTokenSource) {
	case credential.SourceAgentIdentity:
		// Reuse the JWT Warden verified during inbound authentication. It lives
		// in ClientToken only for transparent JWT auth; an opaque session token
		// or a cert-authenticated request has no reusable JWT and fails closed.
		if !strings.HasPrefix(req.ClientToken, "eyJ") {
			return nil, fmt.Errorf("spec %q requires an inbound JWT subject token but the request was not JWT-authenticated", specName)
		}
		inputs.SubjectToken = req.ClientToken
		// No assertion is minted here, so nothing has projected the agent's claims
		// yet — do it for templating alone. Read the token entry rather than
		// re-parsing the JWT: the entry is the auth mount's already-verified view,
		// and a second parse could disagree with what authenticated the request.
		agentClaims, err := projectAgentClaims(te, credential.AssertionMetadataKeys(spec.Config))
		if err != nil {
			return nil, fmt.Errorf("spec %q: %w", specName, err)
		}
		inputs.AgentClaims = agentClaims
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
		setup, err := c.buildAssertionSetup(ctx, specName, spec, te, userTE, assertionSubjectSlot, loadSource)
		if err != nil {
			return nil, err
		}
		inputs.SubjectTokenType = credential.TokenTypeJWT
		inputs.SubjectCacheIdentity = setup.cacheIdentity
		inputs.ResolveSubjectToken = setup.resolve
		// UserClaims/AgentClaims below alias maps the mint closure may marshal
		// concurrently (the chained path's fetchUncached branches mint per request
		// with no coalescing), so they are READ-ONLY from here on. The profile
		// interface documents the profile's half of that contract; this is core's.
		// Surface the projected user claims so the driver can template a per-user
		// request (e.g. kv2_read's secret_path) — the same projection the assertion's
		// user level carries when the user is disclosed to it. Nil unless the spec set
		// assertion_user_claims.
		inputs.UserClaims = setup.userClaims
		inputs.AgentClaims = setup.agentClaims
	default:
		// SpecRequestsExchange already excluded "none"/absent; any other value
		// (including a persisted, now-retired "header") fails closed at mint.
		return nil, fmt.Errorf("spec %q has an unsupported %s %q", specName, credential.ConfigSubjectTokenSource, spec.Config.Get(credential.ConfigSubjectTokenSource))
	}

	switch spec.Config.Get(credential.ConfigActorTokenSource) {
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
		// miss, like the subject assertion. The actor slot never discloses the user
		// to the profile: the token service builds act from this token's sub, so it
		// must name the agent.
		setup, err := c.buildAssertionSetup(ctx, specName, spec, te, userTE, assertionActorSlot, loadSource)
		if err != nil {
			return nil, err
		}
		inputs.ActorTokenType = credential.TokenTypeJWT
		inputs.ActorCacheIdentity = setup.cacheIdentity
		inputs.ResolveActorToken = setup.resolve
		inputs.UserClaims = setup.userClaims
		inputs.AgentClaims = setup.agentClaims
	case credential.SourceNone, "":
		// No actor requested: drop any default type so Validate's pairing holds.
		inputs.ActorTokenType = ""
	default:
		// A persisted spec with a retired actor source (e.g. "header") reaches here
		// at mint time — fail closed rather than silently minting without delegation.
		return nil, fmt.Errorf("spec %q has an unsupported %s %q", specName, credential.ConfigActorTokenSource, spec.Config.Get(credential.ConfigActorTokenSource))
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
	// userClaims is the projected assertion_user_claims map, surfaced so the driver
	// can template a per-user path from them. It is set whenever the spec lists
	// assertion_user_claims — including when the user is NOT disclosed to the
	// assertion (the actor slot, a sub-only verifier's source) — so templating never
	// depends on the claim shape. Nil when the spec sets no assertion_user_claims.
	userClaims map[string]string
	// agentClaims is the primary principal's template map: the projected
	// assertion_metadata_claims plus "sub" (the raw principal). The metadata is
	// what the assertion's agent level carries as warden_metadata, and the raw
	// principal is the trailing segment of the agent's composite sub; both are
	// already inside cacheIdentity, via mdFingerprint and wardenSubject
	// respectively, so templating from it discloses nothing the assertion does not
	// and needs no cache dimension of its own. Never nil: "sub" is unconditional.
	agentClaims map[string]string
}

// assertionSlot is which token of an exchange a Warden assertion fills. It decides
// whether a user can be disclosed to the profile: only the subject token may name
// the user, since the actor token must name the party acting.
type assertionSlot int

const (
	assertionSubjectSlot assertionSlot = iota
	assertionActorSlot
)

// resolveAssertionProfile maps a spec's assertion_profile name onto a registered
// profile, failing closed on a name this build does not have.
//
// The nil-registry case is pinned here rather than left to the issuer's nil-Profile
// fallback, which would otherwise hide it: spec-create validation passes on a nil
// registry, so a spec naming a non-default profile CAN be persisted by a test or
// bootstrap setup. Such a spec must not then quietly mint the default shape — a
// caller that asked for a different claim set getting the old one silently is
// exactly the failure the registry exists to prevent. So: nil registry accepts only
// the default name, and rejects everything else.
func (c *Core) resolveAssertionProfile(name string) (credential.AssertionProfile, error) {
	reg := c.assertionProfileRegistry
	if reg == nil {
		if name == credential.DefaultAssertionProfileName {
			return profiles.Default(), nil
		}
		return nil, fmt.Errorf("assertion profile %q is unavailable (no profile registry)", name)
	}

	return reg.Resolve(name)
}

// buildAssertionSetup validates the OIDC issuer is ready and derives the
// audience, resource, and projected metadata for a warden_identity assertion of
// te, returning a stable cache fragment (identity + audience [+ role]
// [+ resource] [+ metadata]) and a lazy mint closure. The same setup serves a WIF
// subject (the agent IS the identity) and a delegation actor (the agent acts for
// the subject-header user); slot says which, and — with the source's type — decides
// whether the user is disclosed to the profile. loadSource is passed in so the
// spec's source is fetched at most once per request across both slots.
//
// It fails closed if the issuer is disabled/not-ready or no audience can be
// determined. The audience is an explicit spec value or, failing that, one
// derived from the source; resource is unset→derived, "none"→omitted, else
// verbatim; metadata is the operator-allowlisted projection (empty→no claim, so
// the cache key is byte-identical to the no-metadata case).
func (c *Core) buildAssertionSetup(ctx context.Context, specName string, spec *credential.CredSpec, te *logical.TokenEntry, userTE *logical.TokenEntry, slot assertionSlot, loadSource func() (*credential.CredSource, error)) (*assertionSetup, error) {
	issuer := c.OIDCIssuer()
	if issuer == nil || !issuer.Ready() {
		return nil, fmt.Errorf("spec %q requires warden_identity but the OIDC issuer is not enabled/ready", specName)
	}

	// Resolve the claim shape ONCE per request, here — off the signing path. The
	// resolved profile is snapshotted into the mint closure below, so signing takes
	// no registry lock, and a spec naming a profile this build lacks fails here,
	// before any cache interaction.
	profileName := credential.AssertionProfileName(spec.Config)
	profile, err := c.resolveAssertionProfile(profileName)
	if err != nil {
		return nil, fmt.Errorf("spec %q: %w", specName, err)
	}

	// The assertion audience: an explicit spec value wins; otherwise derive it
	// from the source (e.g. a GCP federation source derives it from its
	// workload_identity_provider). Fails closed if neither yields one.
	audience := spec.Config.Get(credential.ConfigAssertionAudience)
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
	switch r := spec.Config.Get(credential.ConfigAssertionResource); r {
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

	// The same projection serves the assertion claim and {{agent.<claim>}}
	// templating, so a template resolves exactly the value a downstream policy can
	// bind — the property the user side states below for the user's claims.
	agentClaims := agentTemplateClaims(projected, te.PrincipalID)

	// Project the secondary (user) principal, but only when the spec opts in via
	// assertion_user_claims — like assertion_metadata_claims, a spec that does not
	// ask never leaks user identity into its assertion. When it asks, a user
	// principal MUST be present and every named claim MUST resolve; both fail
	// closed, since the user's claims scope a security-sensitive downstream path.
	// userClaims (the projected values plus the user's raw principal as "sub") is
	// surfaced on the setup so a driver can template a per-user path from it.
	// Per-user cache isolation is the manager's ":u:" token-id dimension; the
	// user's projected claims enter cacheIdentity as well (userFingerprint),
	// because they are rendered per request from the user mount's naming in
	// force, so a mapping edit changes them under the same user token id.
	//
	// The same opt-in can also DISCLOSE the user to the profile (userIdentity:
	// namespace, mount, principal and the user token's own verified act chain),
	// which makes the user the assertion's subject and the agent its
	// actor. It is disclosed only for the subject slot — an actor token must name
	// the agent, since the token service builds act from its sub — and only when
	// the source's verifier can bind claims beyond iss, sub and aud
	// (subOnlyVerifierSources): the user's raw id needs its warden_namespace bound
	// beside it to be a tenant boundary. Withheld, the assertion keeps the agent's
	// composite sub, and userClaims still drives templating. Projected once, here,
	// and snapshotted into the mint closure.
	var userClaims map[string]string
	var userFingerprint string
	var userIdentity *credential.AssertionIdentity
	if userKeys := credential.AssertionUserClaimKeys(spec.Config); len(userKeys) > 0 {
		if userTE == nil {
			return nil, fmt.Errorf("spec %q sets assertion_user_claims: %w", specName, credential.ErrUserRequired)
		}
		// The raw principal becomes the assertion's sub once disclosed, and feeds
		// {{user.sub}} either way. Refused before both, so no slot, source or cache
		// path can let a user present an agent's subject.
		if credential.HasReservedSubjectPrefix(userTE.PrincipalID) {
			return nil, fmt.Errorf("spec %q: %w", specName, credential.ErrReservedPrincipal)
		}
		// "sub" names the user's identity principal, not a metadata key — exclude it
		// from the metadata projection so an operator can list it (to template
		// {{user.sub}}) without needing a metadata key literally named "sub".
		metaKeys := make([]string, 0, len(userKeys))
		for _, k := range userKeys {
			if k != "sub" {
				metaKeys = append(metaKeys, k)
			}
		}
		projectedUser, fingerprint, perr := projectUserClaims(userTE.Metadata, metaKeys)
		userFingerprint = fingerprint
		if perr != nil {
			return nil, fmt.Errorf("spec %q: %w", specName, perr)
		}
		// One map serves BOTH the assertion's user level and secret_path templating,
		// so {{user.sub}} templates exactly the value a verifier binds as sub. The
		// identity sub (the raw principal) is authoritative and set last.
		userClaims = make(map[string]string, len(projectedUser)+1)
		for k, v := range projectedUser {
			userClaims[k] = v
		}
		userClaims["sub"] = userTE.PrincipalID

		if slot == assertionSubjectSlot {
			src, err := loadSource()
			if err != nil {
				return nil, err
			}
			if !subOnlyVerifierSources[src.Type] {
				uid := identityFromTokenEntry(userTE)
				userIdentity = &uid
			}
		}
	}

	// A profile that cannot truthfully render this pair of principals refuses it
	// here, before cacheIdentity exists and so before any cache lookup. Refusing
	// only at mint would be skipped on a cache hit: the chained-secret cache is
	// identity-keyed and shared across an agent's sessions, so a session the
	// profile must refuse could be served what an acceptable session cached.
	if checker, ok := profile.(credential.AssertionProfileIdentityChecker); ok {
		if err := checker.CheckIdentities(identityFromTokenEntry(te), userIdentity); err != nil {
			return nil, fmt.Errorf("spec %q: assertion profile %q: %w", specName, profile.Name(), err)
		}
	}

	// Key the credential cache on the stable identity + audience, NOT the
	// freshly-minted assertion bytes (which change every request), so one identity
	// reuses its cached upstream credential. Fold in the resource (it can come from
	// source config, which can change under a fixed specName) and the projected-
	// metadata fingerprint. Each fragment is appended only when non-empty, so the
	// no-resource / no-metadata cache keys stay byte-for-byte unchanged; the
	// fragments carry mutually non-prefix leads — "role=", "res=", "user=",
	// "prof=", and the '{' of the marshalled metadata JSON — so one fragment's
	// start cannot be read as another's.
	//
	// That disambiguates starts, not contents: a value holding a NUL could spell a
	// later fragment that is itself absent. Nothing can reach it — role names are
	// restricted to word characters at creation, and audience and resource come from
	// one spec's config — so the alternative, length-prefixing every fragment, would
	// buy an unreachable case at the cost of changing every existing key.
	//
	// The role is folded in because the assertion asserts it (warden_role) and a
	// downstream is invited to authorize on it, so the answer it gives can differ
	// per role while subject, audience, resource and metadata are all identical.
	// Leaving it out let a caller be served a secret fetched under a role it never
	// presented — the chained-secret cache shares a fetch across an agent's
	// sessions by design, and without this fragment two roles are one agent to it.
	// Appended only when set. Minting needs a principal, not a role, so a role-less
	// entry can mint — and one does reach here: every auth method requires a role at
	// login, but a root token is not issued by an auth method and carries no role,
	// and the access path mints for whatever token it is handed. Role-less tokens
	// share one key and assert an empty role, which is consistent (they are
	// indistinguishable to the upstream too), and the conditional keeps every key
	// that predates this fragment byte-identical.
	//
	// The profile is folded in because it decides the claim SHAPE, so two specs with
	// identical identity, audience, role, resource and metadata can still assert
	// materially different things to the upstream — a different `sub`, a promoted
	// user, a dropped claim set — and must not share a cached answer.
	//
	// ONE fragment is enough, and it is worth saying why. Every input a profile can
	// read is already fingerprinted: identity and audience directly, role via
	// "role=", resource via "res=", projected metadata via mdFingerprint, the
	// user's projected claims via "user=", and the user via the Manager's ":u:"
	// token-id dimension. That last one covers the user's IDENTITY: namespace,
	// mount, principal and act chain are all fixed for the life of the user's token
	// entry, and a transparent user token's id hashes the very credential the act
	// chain was read from. (The agent's own act chain is read only to refuse, never rendered, so it
	// keys nothing.) A profile only changes how those are RENDERED, so its name is
	// the single new degree of freedom. Should a later profile ever read something
	// outside that set, it needs a fragment of its own — that is the moment to give
	// the interface a CacheFragment method, not before.
	//
	// This reaches every cache mechanically, with nothing further to remember:
	// cacheIdentity becomes inputs.Subject/ActorCacheIdentity, which
	// ExchangeInputs.Fingerprint() hashes, which keys both the primary cache entry
	// and (as its "fp" component) chainedSecretCacheKey.
	//
	// Appended only for a non-default profile, so every cache key that predates this
	// fragment stays byte-for-byte identical — the same discipline as the fragments
	// above.
	cacheIdentity := wardenSubject(te) + "\x00" + audience
	if te.RoleName != "" {
		cacheIdentity += "\x00role=" + te.RoleName
	}
	if resource != "" {
		cacheIdentity += "\x00res=" + resource
	}
	if mdFingerprint != "" {
		cacheIdentity += "\x00" + mdFingerprint
	}
	// The user's projected claims, which can change under one user token id:
	// they are rendered from the user mount's naming in force.
	if userFingerprint != "" {
		cacheIdentity += "\x00user=" + userFingerprint
	}
	// Keyed on the RESOLVED profile's Name(), not the config string that selected
	// it. Identical today, but it keeps an alias possible later: were two config
	// names ever to resolve to one profile (say, after a rename), they would share
	// one cache dimension rather than splitting it — which is the only objection
	// the naming rules raise against aliases.
	if name := profile.Name(); name != credential.DefaultAssertionProfileName {
		cacheIdentity += "\x00prof=" + name
	}

	// The spec selects the assertion signing algorithm (default RS256). The issuer
	// maintains a keyset per algorithm, so either is available with no cold start;
	// validation restricts it to a supported alg at spec-create. The mint itself is
	// deferred to a cache MISS (invoked by the Manager's singleflight leader), so at
	// most one assertion is minted per miss and none on the hot path.
	alg := credential.AssertionAlgorithm(spec.Config)
	// The spec may request a shorter assertion lifetime (assertion_ttl). It is only
	// a request: the issuer caps it at its own AssertionTTL(), so a spec can never
	// mint past the issuer's lifetime. Parsed once here (the spec config is
	// fixed for this request); the issuer default is read inside the closure, at
	// mint time, so a runtime change to it is honoured.
	//
	// Not a cache dimension: exp is volatile by design (see the claim roster), the
	// primary cache key already carries the spec name, and the chained key hashes
	// the spec config, so an edit to this value refills chained entries as it should.
	requestedTTL := credential.RequestedAssertionTTL(spec.Config)
	return &assertionSetup{
		cacheIdentity: cacheIdentity,
		userClaims:    userClaims,
		agentClaims:   agentClaims,
		resolve: func(ctx context.Context) (string, error) {
			ttl := requestedTTL
			if ttl == 0 {
				ttl = issuer.AssertionTTL()
			}
			return issuer.MintIdentityAssertion(ctx, te, AssertionClaims{
				Audience:   audience,
				TTL:        ttl,
				Alg:        alg,
				Metadata:   projected,
				Resource:   resource,
				UserClaims: userClaims,
				User:       userIdentity,
				Profile:    profile,
			})
		},
	}, nil
}

// mintCredentialForRequest mints credentials for requests using the credential manager
// callerFor carries the requesting identity through the mint pipeline so a chained
// secret-spec (credential chaining) is minted as this same caller.
//
// ResolveInputs resolves token-exchange inputs for an arbitrary spec as this caller
// (nil for non-exchange specs), reused both for the request's own spec and, by the
// Manager, for any referenced secret-spec. It must resolve from THIS token entry:
// the identity it derives keys the chained-secret cache, which shares one fetch
// across an agent's sessions rather than asking the store again, so an entry
// reconstructed from anything less than the live one — losing the role, say — would
// hand a caller a secret fetched under an identity it never presented.
func (c *Core) callerFor(req *logical.Request, te *logical.TokenEntry, tokenTTL time.Duration, userCtx *credential.UserContext) credential.Caller {
	return credential.Caller{
		TokenID:  te.ID,
		TokenTTL: tokenTTL,
		User:     userCtx,
		ResolveInputs: func(ctx context.Context, specName string) (*credential.ExchangeInputs, error) {
			return c.resolveExchangeInputs(ctx, req, te, specName)
		},
	}
}

func (c *Core) mintCredentialForRequest(ctx context.Context, req *logical.Request, te *logical.TokenEntry) error {
	if te == nil {
		return logical.ErrInternal("cannot mint credential since token entry is nil")
	}
	return c.mintSpecForRequest(ctx, req, te, te.CredentialSpec)
}

// mintSpecForRequest mints specName for the request, as the caller te
// identifies. The spec is a parameter, never written into te, because te may be
// shared: an implicit login coalesced through one flight hands the same entry to
// every request that waited on it, so a request-specific spec stored there (an
// access grant's, say) would race with the others and could mint one request's
// grant for another.
func (c *Core) mintSpecForRequest(ctx context.Context, req *logical.Request, te *logical.TokenEntry, specName string) error {
	if te == nil {
		return logical.ErrInternal("cannot mint credential since token entry is nil")
	}
	if specName == "" {
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
	if !c.credentialManager.SpecExists(ctx, specName) {
		c.logger.Warn("credential spec not found or disabled",
			logger.String("token_id", te.ID),
			logger.String("spec_name", specName),
		)
		return logical.ErrBadRequestf("credential spec %q not found or disabled", specName)
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
	// consumed (the assertion's user level), not duplicated here.
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

	caller := c.callerFor(req, te, tokenTTL, userCtx)

	// Resolve any caller-supplied token-exchange inputs the spec opts into.
	// Returns nil for non-exchange specs, leaving the mint path unchanged.
	inputs, err := caller.ResolveInputs(ctx, specName)
	if err != nil {
		return exchangeInputError(err)
	}

	// Issue credential using the credential manager
	// Credentials are cache-only (not persisted) - ExpirationEntry handles lease revocation
	cred, err := c.credentialManager.IssueCredential(ctx, caller, specName, inputs)
	if err != nil {
		// Typed so a gateway error renderer can tell a credential-issuance
		// failure from the others that share its status; Error() is unchanged.
		return &logical.CredentialIssueError{Spec: specName, Err: err}
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
// while producing a user nobody reads. Streaming gateway requests, and requests
// on an access backend's transparent surface, use the routed backend's
// ExtractTokens instead.
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
	//   4. Provider default_role (a namespace role)
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

	// Provider default_role.
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

// handleTransparentAuth performs implicit authentication for gateway and access requests.
// It delegates to performImplicitAuth for credential detection and login. An
// empty authRole (no role in the request and no provider default_role) is
// refused there with errNoRoleSelected, before the credential is admitted.
func (c *Core) handleTransparentAuth(ctx context.Context, req *logical.Request, backend logical.Backend, authRole string) error {
	tmp := backend.(logical.TransparentModeProvider)
	autoAuthPath := tmp.GetAutoAuthPath()
	return c.performImplicitAuth(ctx, req, autoAuthPath, authRole)
}

// authenticateImplicitly is the one entry point for a provider's implicit
// authentication, whichever surface the request arrived on: a streaming gateway
// path or an access backend's access path. The caller has already decided, via
// isTransparentRequest, that backend authenticates this request implicitly and
// under which role. It returns nil once the agent is authenticated, or the
// response to answer with when it is not (providerImplicitAuthFailure): 400
// with noRole (the surface's own wording) for a request that selects no role,
// 401 for any other failure.
func (c *Core) authenticateImplicitly(ctx context.Context, req *logical.Request, backend logical.Backend, authRole, noRole string) *logical.Response {
	err := c.handleTransparentAuth(ctx, req, backend, authRole)
	if err == nil {
		return nil
	}
	c.logger.Warn("implicit authentication failed",
		logger.Err(err),
		logger.String("path", req.Path),
		logger.String("operation", string(req.Operation)),
		logger.String("request_id", req.RequestID),
	)
	return providerImplicitAuthFailure(req, err, noRole)
}

// providerTransparentSurface reports whether a request that takes the
// non-streaming branch is nonetheless served on its provider's transparent
// surface, so that the provider authenticates it implicitly. That is the case
// for an access backend's access paths: they vend credentials in an ordinary
// response, so they are not streaming paths, yet they are where agents call.
//
// It returns the routed provider and the auth role isTransparentRequest
// resolved, under the same rules as a gateway path: the provider must have an
// auto_auth_path, the path must be on its transparent surface, and an explicit
// X-Warden-Token opts out. Only provider mounts are consulted, so system and
// auth paths cost no extra lookup; help requests are answered from the path
// schema and never authenticate implicitly, as on the streaming branch.
func (c *Core) providerTransparentSurface(ctx context.Context, req *logical.Request, entry *MountEntry) (logical.Backend, string, bool) {
	if entry == nil || entry.Class != mountClassProvider || req.Operation == logical.HelpOperation {
		return nil, "", false
	}
	backend := c.router.MatchingBackend(ctx, req.Path)
	if backend == nil {
		return nil, "", false
	}
	isTransparent, authRole := c.isTransparentRequest(req, backend)
	if !isTransparent {
		return nil, "", false
	}
	return backend, authRole, true
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
//
// The user is admitted like any credential, with no role, and is granted
// nothing: no role grant, no policies. What it carries is its principal (the
// user auth mount's claim, from the login) and its metadata, rendered from its
// admission under the user auth mount's naming in force (userMetadata). Its
// token's audience must be bound (checkUserAudience), and refusal, the
// provider's own reason to refuse every user credential, refuses this one.
// Both of those are a *userLegRefusal when no other credential would pass.
func (c *Core) captureUserContext(ctx context.Context, req *logical.Request, userAuthPath string, refusal error, userCred string) error {
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

	if refusal != nil {
		return &userLegRefusal{err: refusal}
	}

	userTE, _, err := c.resolveTransparentIdentity(ctx, req, userAuthPath, userCred)
	if err != nil {
		return fmt.Errorf("user authentication failed: %w", err)
	}

	// Cross-namespace guard (defense-in-depth): the user must live in the
	// request's namespace. resolveTransparentIdentity routes through the mount in
	// the request namespace, so a mismatch should not arise — fail closed if it does.
	ns, nsErr := namespace.FromContext(ctx)
	if nsErr != nil || ns == nil {
		return fmt.Errorf("user authentication failed: no namespace in the request")
	}
	if userTE.NamespaceID != ns.ID {
		return fmt.Errorf("user token namespace %q does not match request namespace %q", userTE.NamespaceID, ns.ID)
	}

	// Every token the user mount issues is an admission token, and every
	// decision below reads its admission: one without is refused.
	adm := userTE.Admission
	if adm == nil {
		return errUserNoAdmission
	}
	if err := c.checkUserAudience(ctx, adm, ns.Path, req.MountPoint, userAuthPath); err != nil {
		return err
	}

	// userTE is this request's own copy, so the metadata set here reaches
	// this request alone.
	userTE.Metadata = userMetadata(adm)

	req.User = &logical.UserPrincipal{
		TokenEntry: userTE,
		RawToken:   userCred,
	}
	return nil
}

// userCaptureFailure is the response to a request whose user credential
// captureUserContext refused with err.
func (c *Core) userCaptureFailure(ctx context.Context, req *logical.Request, err error) *logical.Response {
	// The mount's configuration refuses every user credential: nothing the
	// client presents instead would pass, so there is no challenge to answer
	// with.
	var refused *userLegRefusal
	if errors.As(err, &refused) {
		return logical.ErrorResponse(logical.ErrForbidden(err.Error()))
	}
	// A user credential WAS presented and rejected, so the challenge carries
	// error="invalid_token" — the client should replace it rather than assume
	// it simply forgot to send one.
	errResp := logical.ErrorResponse(logical.ErrUnauthorized(err.Error()))
	c.attachUserChallenge(ctx, req, errResp, true)
	return errResp
}

// userLegRefusal is a user credential refused for the provider's configuration
// rather than for anything about the credential: no other credential would
// pass, so the request is refused without a challenge to obtain one.
type userLegRefusal struct{ err error }

func (r *userLegRefusal) Error() string { return r.err.Error() }
func (r *userLegRefusal) Unwrap() error { return r.err }

var (
	// errUserNoAdmission refuses a user token that carries no admission. The
	// user mount's logins always attach one, so this is defense in depth.
	errUserNoAdmission = errors.New("user authentication failed: the user token carries no admission")

	// errUserAudienceNotResource refuses a user token minted for another
	// resource than the one requested.
	errUserAudienceNotResource = errors.New("user token audience does not name this resource")
)

// factAudience is the fact naming a credential's audiences.
const factAudience = "aud"

// checkUserAudience decides whether a user token's audience is bound to this
// request's resource, in order:
//
//  1. the user auth mount checked it against its bound_audiences when it
//     admitted the token (adm.AudienceBound);
//  2. otherwise, with protected-resource metadata on (an external base is
//     configured; the mount opted in by setting user_auth_path), the token's
//     aud facts must contain this mount's resource identifier exactly
//     (resourceIDMatches), else errUserAudienceNotResource;
//  3. otherwise nothing binds it, and the request is refused as a
//     *userLegRefusal.
//
// mountPath is the request's namespace-relative mount ("github/"), nsPath its
// namespace path. It does not allocate unless it refuses.
func (c *Core) checkUserAudience(ctx context.Context, adm *logical.Admission, nsPath, mountPath, userAuthPath string) error {
	if adm.AudienceBound {
		return nil
	}
	base := c.externalBaseURL(ctx)
	if base == "" {
		return &userLegRefusal{err: fmt.Errorf("user token audience is not bound: set bound_audiences on %s or enable protected-resource metadata", userAuthPath)}
	}
	aud := adm.Lookup(adm.Mount.Load(), factAudience)
	for {
		v, ok := aud.Next()
		if !ok {
			return errUserAudienceNotResource
		}
		if v.Kind == selector.KindString && resourceIDMatches(v.S, base, nsPath, mountPath) {
			return nil
		}
	}
}

// userMetadata renders the user's metadata from its admission under the user
// auth mount's naming in force. It is cached on the admission through the
// membership mechanism, with no groups to match: the steady state is a pointer
// compare and does not allocate, and a mapping edit on the user mount (facts,
// entity_kind) renders afresh on the next request. The returned map is shared
// and must not be modified.
//
// It takes no instant and reads no clock: with no groups, nothing in the
// membership can expire (its ValidUntil is zero) and compute matches no rule,
// so the zero time decides nothing, and a request reads the clock for a
// membership once, for the agent leg's grant (resolveRoleGrant).
//
// When one agent-kind mount serves as both auto_auth_path and user_auth_path
// (a configuration its provider's config read warns about), a credential
// presented on both legs shares one admission, whose cached membership then
// alternates between the user leg's (no groups) and the agent leg's (the
// namespace's groups): each leg recomputes on the other's cache and the
// zero-allocation steady state is lost, but each request still gets the
// membership of its own leg, so correctness is not affected.
func userMetadata(adm *logical.Admission) map[string]string {
	return membership(adm, emptyNSGroups, time.Time{}).Metadata
}

// resolveUserAuthConfig resolves the secondary (user) auth configuration for a
// gateway request from the mount's own config (a backend that implements
// logical.UserAuthConfigProvider). Returns an empty path when per-user auth is
// not configured on this mount, and refusal, the provider's reason to refuse
// every user credential, when it has one.
//
// Deliberately mount-only, unlike auto_auth_path, which also falls back to the
// namespace's custom metadata. Agent identity genuinely is namespace-scoped —
// every workload in a namespace authenticates the same way — but user_auth_path
// marks THIS mount as a protected resource: it decides whether Authorization
// carries the user rather than the agent, and it binds one resource to one
// identity provider and audience. A namespace-wide fallback would opt in every
// mount in the namespace, including ones that never intended to reinterpret
// Authorization, and would bind one audience to every resource at once.
func (c *Core) resolveUserAuthConfig(_ context.Context, backend logical.Backend) (userAuthPath string, refusal error) {
	if p, ok := backend.(logical.UserAuthConfigProvider); ok {
		userAuthPath = p.GetUserAuthPath()
		refusal = p.UserAuthRefusal()
	}
	return userAuthPath, refusal
}

// providerConfigWarnings returns what the config read of the provider mounted
// at entry warns about: its user leg (userLegConfigWarnings), and an auth path
// naming a mount of the wrong kind (authMountKindWarnings).
func (c *Core) providerConfigWarnings(ctx context.Context, entry *MountEntry) []string {
	warnings := c.userLegConfigWarnings(ctx, entry)
	return append(warnings, c.authMountKindWarnings(ctx, c.router.MatchingBackend(ctx, entry.Path))...)
}

// authMountKindWarnings returns a warning when the provider backend's
// auto_auth_path names a human auth mount (the agent leg never admits through
// one, so every gateway request is refused), and one when its user_auth_path
// names an agent auth mount. Each path is resolved as the request path
// resolves it; a path naming no mount, or a mount that publishes no naming, is
// not warned about here.
func (c *Core) authMountKindWarnings(ctx context.Context, backend logical.Backend) []string {
	var warnings []string
	if tmp, ok := backend.(logical.TransparentModeProvider); ok {
		if path := tmp.GetAutoAuthPath(); path != "" && c.authMountKind(ctx, path) == logical.EntityKindHuman {
			warnings = append(warnings, fmt.Sprintf("auto_auth_path %q names a human auth mount: "+
				"agent credentials are never admitted through it, so every gateway request is refused", path))
		}
	}
	if path, _ := c.resolveUserAuthConfig(ctx, backend); path != "" &&
		c.authMountKind(ctx, normalizeAuthPath(path)) == logical.EntityKindAgent {
		warnings = append(warnings, fmt.Sprintf("user_auth_path %q names an agent auth mount: "+
			"user credentials are expected through a human auth mount", path))
	}
	return warnings
}

// authMountKind returns the entity kind the auth mount at path admits under
// its current configuration, or "" when path names no auth mount or the mount
// publishes no naming.
func (c *Core) authMountKind(ctx context.Context, path string) string {
	if e := c.router.MatchingMountEntry(ctx, path); e == nil || e.Class != mountClassAuth {
		return ""
	}
	if fp, ok := c.router.MatchingBackend(ctx, path).(logical.FactsProvider); ok {
		return fp.EntityKind()
	}
	return ""
}

// userLegConfigWarnings returns what the config read of the provider mounted
// at entry warns about its user leg: a stored configuration that refuses every
// user credential (UserAuthRefusal), or a user token audience nothing binds,
// neither the user auth mount's bound_audiences nor this mount's resource
// identifier (checkUserAudience refuses every user credential then). A
// provider with no user leg warns of nothing.
func (c *Core) userLegConfigWarnings(ctx context.Context, entry *MountEntry) []string {
	userAuthPath, refusal := c.resolveUserAuthConfig(ctx, c.router.MatchingBackend(ctx, entry.Path))
	if userAuthPath == "" {
		return nil
	}
	if refusal != nil {
		return []string{"user credentials are refused: " + refusal.Error()}
	}
	authPath := normalizeAuthPath(userAuthPath)
	if c.router.MatchingMountEntry(ctx, authPath) != nil {
		if binder, ok := c.router.MatchingBackend(ctx, authPath).(logical.AudienceBinder); ok && binder.BindsAudience() {
			return nil
		}
	}
	if c.externalBaseURL(ctx) != "" {
		return nil
	}
	return []string{fmt.Sprintf("user token audience is not bound: set bound_audiences on %s or enable "+
		"protected-resource metadata; until then every user credential is refused", authPath)}
}

// performImplicitAuth performs implicit authentication for the PRIMARY principal
// (the agent) by routing the request's own credential through the auth mount the
// caller's namespace/provider points at. It delegates the credential→TokenEntry
// resolution to resolveTransparentIdentity and then applies the request mutations
// that mark the resolved token as this request's primary principal
// (req.Transparent, req.SetTokenEntry, and the ClientToken assignment). Used by
// both gateway requests and transparent operations.
//
// A request that selects no role is refused before the credential is admitted:
// nothing is logged in and nothing is cached. It is refused with
// errNoImplicitCredential when it carries no credential at all (the client
// must authenticate first), else with errNoRoleSelected. A
// credential admitted through a mount whose entity kind is human is refused
// with errHumanMountOnAgentLeg before the token is set on req: a human mount
// may admit without an audience binding of its own, so it never carries the
// agent leg.
func (c *Core) performImplicitAuth(ctx context.Context, req *logical.Request, autoAuthPath, authRole string) error {
	if authRole == "" {
		// Presence only, from the request alone: a token or a client
		// certificate the listener already parsed. Nothing is verified.
		if req.ClientToken == "" && extractTransparentClientCert(req) == nil {
			return errNoImplicitCredential
		}
		return errNoRoleSelected
	}

	// Mark request as implicit auth
	req.Transparent = true

	te, clearClientToken, err := c.resolveTransparentIdentity(ctx, req, autoAuthPath, "")
	if err != nil {
		return err
	}

	// One atomic load of the mount's naming in force: a mount flipped to
	// agent admits on the next request, one flipped to human is refused on
	// the next request, whatever its cached admissions. A mount publishing no
	// naming (facts that do not compile) answers no fact, so no group grants
	// through it and resolveRoleGrant refuses the request.
	if te.Admission != nil {
		if n := te.Admission.Mount.Load(); n != nil && n.Kind == logical.EntityKindHuman {
			return errHumanMountOnAgentLeg
		}
	}

	// The X.509-SVID case authenticates via a forwarded/TLS cert; drop any stray
	// non-SVID bearer so the cert-minted token ID becomes ClientToken below.
	if clearClientToken {
		req.ClientToken = ""
	}
	req.SetTokenEntry(te)
	// The role this request asks for, for CheckToken to grant: the token is
	// an admission token, which carries no role of its own. With
	// req.Transparent, set above, it is also what tells CheckToken the token
	// came from admitting this request's own credential, not from a Warden
	// token presented explicitly. A string, so recording it allocates nothing.
	req.RequestedRole = authRole
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
//	  - Gateway and access paths: provider auto_auth_path config
//	  - Operations: namespace auto_auth_path metadata
//
//	Inside this function:
//	  1. Resolve the mount and its backend at autoAuthPath, in one router
//	     lookup. Reject if no mount is registered.
//	  2. Ask the backend for its credential format
//	     (logical.CredentialFormatProvider). Reject if it reports none — that
//	     means the mount doesn't support implicit auth.
//	  3. Dispatch on that format to extract the credential the mount expects
//	     (TLS client cert vs JWT bearer). Reject with a specific error if the
//	     caller didn't present that credential.
//	  4. Look up the identity token cached for (mountAccessor, credential),
//	     falling through to an internal login on miss.
//
// The token is an admission token: one per credential and mount, whatever role
// a request asks for. The role is not part of the login, the cache key or the
// singleflight key; CheckToken grants it per request on the copy returned here
// (resolveRoleGrant), so requests for two roles share the one admission.
//
// Uses singleflight to prevent duplicate token creation when concurrent requests
// arrive with the same credential at the same mount. Every waiter gets its own
// copy of the entry, sharing the one *Admission.
func (c *Core) resolveTransparentIdentity(ctx context.Context, req *logical.Request, autoAuthPath, credential string) (te *TokenEntry, clearClientToken bool, err error) {
	// Inject client IP into context so validateIPBinding can read it
	// during cached token lookups. Without this, implicitly-authed tokens
	// bypass IP binding because the context has no client IP.
	if req.ClientIP != "" {
		ctx = context.WithValue(ctx, logical.ClientIPKey, req.ClientIP)
	}

	// A non-empty credential is the secondary (user) path: the mount must be a
	// bearer format, and the credential is used verbatim as the bearer token.
	explicitCred := credential != ""

	// Resolve the auth mount and its backend in one lookup. The backend names
	// the credential format it admits; the entry supplies the stable mount
	// accessor folded into the cache key.
	authMountEntry, authBackend := c.router.MatchingMountEntryAndBackend(ctx, autoAuthPath)
	if authMountEntry == nil {
		return nil, false, fmt.Errorf("no auth mount registered at %q for implicit auth", autoAuthPath)
	}
	mountAccessor := authMountEntry.Accessor

	// A backend that names no credential format is not a transparent auth
	// method: reject the request explicitly rather than silently falling back
	// to credential-format sniffing.
	formatProvider, ok := authBackend.(logical.CredentialFormatProvider)
	if !ok {
		return nil, false, fmt.Errorf("auth method %q at %q does not support implicit auth", authMountEntry.Type, autoAuthPath)
	}
	credentialFormat := formatProvider.CredentialFormat()

	var singleflightKey string
	// lookupFunc takes its ctx rather than closing over the request's: inside the
	// singleflight it runs on the login's detached context.
	var lookupFunc func(ctx context.Context) (*TokenEntry, error)
	var loginData map[string]any
	var credKey string // fingerprint or JWT — used for the post-login lookup

	// Dispatch by the credential's wire-extraction shape. Cases group by what
	// the credential looks like on the wire (cert vs JWT bearer): a generic JWT
	// and a Kubernetes service account JWT both arrive as JWTs in the
	// Authorization header and share the same parse path. The cache key is per
	// mount, so formats sharing an extraction case never share an entry.
	switch credentialFormat {
	case logical.CredentialFormatCert:
		if explicitCred {
			return nil, false, fmt.Errorf("auth method %q at %q requires a bearer credential, not a TLS client certificate", authMountEntry.Type, autoAuthPath)
		}
		clientCert := extractTransparentClientCert(req)
		if clientCert == nil {
			return nil, false, fmt.Errorf("auth method %q at %q requires a TLS client certificate", authMountEntry.Type, autoAuthPath)
		}
		hash := sha256.Sum256(clientCert.Raw)
		fingerprint := hex.EncodeToString(hash[:])
		sfHash := sha256.Sum256([]byte("cert:" + mountAccessor + ":" + fingerprint))
		singleflightKey = hex.EncodeToString(sfHash[:])
		loginData = map[string]any{}
		credKey = fingerprint
		// Authenticate via the client certificate, not any bearer. Signal the
		// primary caller to drop a stray Authorization bearer (ExtractToken falls
		// back to Authorization, so a cert request that also carries a bearer —
		// e.g. a secondary user token on Authorization — would otherwise leave that
		// bearer, not the cert-minted token ID, in ClientToken).
		clearClientToken = true
		lookupFunc = func(ctx context.Context) (*TokenEntry, error) {
			return c.LookupTransparentToken(ctx, fingerprint, mountAccessor)
		}

	case logical.CredentialFormatJWT, logical.CredentialFormatKubernetesJWT:
		clientToken := credential
		if clientToken == "" {
			clientToken = req.ClientToken
		}
		if !strings.HasPrefix(clientToken, "eyJ") {
			return nil, false, fmt.Errorf("auth method %q at %q requires a JWT bearer token", authMountEntry.Type, autoAuthPath)
		}
		sfHash := sha256.Sum256([]byte("jwt:" + mountAccessor + ":" + clientToken))
		singleflightKey = hex.EncodeToString(sfHash[:])
		loginData = map[string]any{"jwt": clientToken}
		credKey = clientToken
		lookupFunc = func(ctx context.Context) (*TokenEntry, error) {
			return c.LookupTransparentToken(ctx, clientToken, mountAccessor)
		}

	case logical.CredentialFormatSPIFFE:
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
		if spiffelib.IsJWTSVID(clientToken) {
			sfHash := sha256.Sum256([]byte("spiffe-jwt:" + mountAccessor + ":" + clientToken))
			singleflightKey = hex.EncodeToString(sfHash[:])
			loginData = map[string]any{"jwt": clientToken}
			credKey = clientToken
			lookupFunc = func(ctx context.Context) (*TokenEntry, error) {
				return c.LookupTransparentToken(ctx, clientToken, mountAccessor)
			}
		} else if explicitCred {
			// The secondary (user) path is bearer-only; an X.509-SVID can't ride a
			// header, so a non-SVID credential here is a misconfigured user mount.
			return nil, false, fmt.Errorf("auth method %q at %q requires a JWT-SVID bearer credential", authMountEntry.Type, autoAuthPath)
		} else if clientCert := extractTransparentClientCert(req); clientCert != nil {
			hash := sha256.Sum256(clientCert.Raw)
			fingerprint := hex.EncodeToString(hash[:])
			sfHash := sha256.Sum256([]byte("spiffe-cert:" + mountAccessor + ":" + fingerprint))
			singleflightKey = hex.EncodeToString(sfHash[:])
			loginData = map[string]any{}
			credKey = fingerprint
			// Authenticate via the X.509-SVID, not any bearer. Signal the primary
			// caller to clear a stray non-SVID bearer so the cert-minted token ID
			// becomes ClientToken (this function performs no request mutation).
			clearClientToken = true
			lookupFunc = func(ctx context.Context) (*TokenEntry, error) {
				return c.LookupTransparentToken(ctx, fingerprint, mountAccessor)
			}
		} else {
			return nil, false, fmt.Errorf("auth method %q at %q requires an X.509-SVID (TLS/forwarded cert) or a JWT-SVID bearer token", authMountEntry.Type, autoAuthPath)
		}

	default:
		return nil, false, fmt.Errorf("auth method %q has unsupported credential format %q for implicit auth", authMountEntry.Type, credentialFormat)
	}

	// Step 1: Try cached lookup
	// Note: cached tokens are returned without re-checking certificate revocation.
	// This is an accepted design trade-off — revocation is a best-effort signal and
	// the token TTL (default 1h) bounds the exposure window. Explicit login requests
	// always perform full revocation checks. To reduce exposure for revoked certs,
	// configure a shorter token_ttl on cert roles.
	te, err = lookupFunc(ctx)
	if err == nil && te != nil {
		return te, clearClientToken, nil
	}

	// IP binding violation means the token exists but the client IP doesn't match.
	// Return the error immediately — don't fall through and create a new token.
	if err == ErrOriginViolation {
		return nil, false, err
	}

	// Step 2: Token not found — perform the implicit auth, once for every request
	// presenting this credential to this mount. transparentAuthFlight runs it detached
	// from the request that started it, so that request's client going away does
	// not fail the others; the context keeps its values, the client IP set above
	// among them. Each caller waits on its own ctx.
	te, err = c.transparentAuthFlight.Do(ctx, singleflightKey, func(ctx context.Context) (*TokenEntry, error) {
		// Double-check: another goroutine may have just created the token
		checkTE, lookupErr := lookupFunc(ctx)
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

		// Look the issued token up by its cache key, so the entry handed out
		// is the one the cache holds (a concurrent login for this credential
		// may have issued it), with that entry's admission.
		newTE, postErr := c.LookupTransparentToken(ctx, credKey, mountAccessor)
		if postErr != nil {
			return nil, fmt.Errorf("failed to lookup created token: %w", postErr)
		}

		return newTE, nil
	})
	if err != nil {
		return nil, false, err
	}
	// The flight hands one entry to every request that waited on it. Each gets
	// its own copy, since a request writes onto its entry (its role, or an
	// access backend's spec); the copies share the one *Admission, as every
	// copy of a token entry does. One allocation per waiter on a cache miss
	// (the flight's shared result is itself a copy).
	return te.Copy(), clearClientToken, nil
}

// transparentLoginTimeout bounds an implicit login, which runs detached from the
// requests waiting on it. It covers fetching the IdP's keys (OIDC discovery and
// JWKS) on a cold cache.
const transparentLoginTimeout = 30 * time.Second

// transparentLoginMaxDetached caps the implicit logins running detached at once.
// Their key is the credential presented, chosen before anyone has checked it, so
// without a cap every request sent with a fresh bearer and dropped would leave a
// login running for up to transparentLoginTimeout. Past the cap a login runs on
// the context of the request that started it, as before logins were detached. A
// node has far fewer distinct credentials logging in at once than this.
const transparentLoginMaxDetached = 256

// newTransparentAuthFlight builds the group implicit logins are coalesced through.
// A login still in flight ends with the node's active term, as the requests it
// serves do, instead of running on past a seal or a step-down.
func newTransparentAuthFlight(c *Core) *flight.Group[*TokenEntry] {
	return flight.New[*TokenEntry]("implicit login", transparentLoginTimeout, c.logger,
		flight.WithLifetime(func() context.Context { return c.activeContext }),
		flight.WithMaxDetached(transparentLoginMaxDetached))
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
