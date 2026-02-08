package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-multierror"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/pathmanager"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
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
			if c.standby.Load() {
				return nil, cbp, te, sdklogical.ErrPerfStandbyPleaseForward
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

	if !accessControlResults.Allowed {
		retErr := accessControlResults.Error

		if accessControlResults.Error.ErrorOrNil() == nil || accessControlResults.DeniedError {
			retErr = multierror.Append(retErr, sdklogical.ErrPermissionDenied)
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
				errors.Is(err, ErrOriginViolation) {
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
			return logical.ErrorResponse(logical.ErrServiceUnavailable("standby node, please forward to active")), nil
		}
		return logical.ErrorResponse(logical.ErrServiceUnavailable("server context canceled")), nil
	}

	// Extract namespace header from HTTP request
	var nsHeader string
	if req.HTTPRequest != nil {
		nsHeader = req.HTTPRequest.Header.Get("X-Warden-Namespace")
	}

	// Sanitize the request path
	requestPath := strings.TrimSuffix(req.Path, "/")

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
		resp, auth, err = c.handleLoginRequest(ctx, req)
		te = req.TokenEntry()
	} else {
		resp, auth, err = c.handleNonLoginRequest(ctx, req)
		te = req.TokenEntry()
	}

	if resp != nil && resp.Streamed {
		if srw, ok := req.ResponseWriter.(*logical.StatusRecordingWriter); ok {
			resp.StatusCode = srw.StatusCode()
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
func (c *Core) handleLoginRequest(ctx context.Context, req *logical.Request) (retResp *logical.Response, retAuth *logical.Auth, retErr error) {

	req.Unauthenticated = true

	entry := c.router.MatchingMountEntry(ctx, req.Path)
	if entry != nil {
		// Set here so the audit log has it even if authorization fails
		req.MountType = entry.Type
		req.MountClass = entry.Class
		req.MountAccessor = entry.Accessor
	}

	// Parse request body before CheckToken since req.Data may be used during token validation
	if err := c.parseRequestBody(req); err != nil {
		return logical.ErrorResponse(logical.ErrBadRequest(err.Error())), nil, err
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

	// If the response generated an authentication, then generate the token
	if resp != nil && resp.Auth != nil {
		respTokenCreate, errCreateToken := c.LoginCreateToken(ctx, resp)
		if errCreateToken != nil {
			return respTokenCreate, nil, errCreateToken
		}
		resp = respTokenCreate
		resp.MountClass = req.MountClass
	}

	if routeErr != nil {
		retErr = multierror.Append(retErr, routeErr)
	}

	return resp, auth, routeErr
}

func (c *Core) LoginCreateToken(ctx context.Context, resp *logical.Response) (*logical.Response, error) {
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

	now := time.Now()
	authData := logical.AuthData{
		PrincipalID:    auth.PrincipalID,
		RoleName:       auth.RoleName,
		ExpireAt:       now.Add(auth.TokenTTL),
		CredentialSpec: auth.CredentialSpec,
		Policies:       auth.Policies,
		ClientIP:       auth.ClientIP,
		TokenValue:     auth.ClientToken,
	}

	tokenValue, err := c.tokenStore.GenerateToken(ctx, auth.TokenType, &authData)

	if err != nil {
		// error when creating token
		c.logger.Error("Failed to generate token", logger.String("token_type", auth.TokenType), logger.Any("auth_data", authData))
		return logical.ErrorResponse(logical.ErrInternal("failed to generate token")), ErrInternalError
	}

	data := map[string]any{
		"token_type":     tokenValue.Type,
		"expire_at":      tokenValue.ExpireAt,
		"bound_ip":       tokenValue.CreatedByIP,
		"token_id":       tokenValue.ID,
		"token_assessor": tokenValue.Accessor,
		"namespace":      tokenValue.NamespacePath,
		"role":           tokenValue.RoleName,
		"data":           tokenValue.Data,
		"policies":       tokenValue.Policies,
	}

	maps.Copy(resp.Data, data)

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

	// Parse request body before CheckToken since req.Data may be used during policy evaluation
	isStreaming := c.isStreamingRequest(ctx, req.Path)

	if !isStreaming {
		if err := c.parseRequestBody(req); err != nil {
			return logical.ErrorResponse(logical.ErrBadRequest(err.Error())), nil, err
		}
		req.ClientToken = extractToken(req.HTTPRequest)
	} else {
		req.Streamed = true
		req.Operation = logical.StreamOperation

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

		req.ClientToken = matchingBackend.ExtractToken(req.HTTPRequest)

		// Check for unauthenticated paths on streaming backends
		if req.ClientToken == "" {
			if tmp, ok := matchingBackend.(logical.TransparentModeProvider); ok {
				relativePath := req.Path
				if req.MountPoint != "" {
					relativePath = strings.TrimPrefix(req.Path, req.MountPoint)
				}
				if tmp.IsUnauthenticatedPath(relativePath) {
					req.StreamUnauthenticated = true
					c.logger.Trace("unauthenticated streaming request",
						logger.String("path", req.Path),
					)
				}
			}
		}

		// Check for transparent mode and perform implicit auth if needed
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

					return logical.ErrorResponse(logical.ErrUnauthorized(err.Error())), nil, nil
				}
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
			c.logger.Warn("error when checking token", logger.Err(ctErr))
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
			return logical.ErrorResponse(logical.ErrInternalf("failed to mint credential: %s", err.Error())), auth, err
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

	// Parse JSON body (overwrites query params with same keys)
	return c.parseJSONBody(req)
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

	body, err := io.ReadAll(req.HTTPRequest.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	req.HTTPRequest.Body.Close()

	// Restore body for potential re-reading (audit, streaming, etc.)
	req.HTTPRequest.Body = io.NopCloser(bytes.NewReader(body))

	if len(body) == 0 {
		return nil
	}

	return json.Unmarshal(body, &req.Data)
}

// mintCredentialForRequest mints credentials for streaming requests using the credential manager
func (c *Core) mintCredentialForRequest(ctx context.Context, req *logical.Request, te *logical.TokenEntry) error {
	if te == nil {
		return fmt.Errorf("cannot mint credential since token entry is nil")
	}
	if te.CredentialSpec == "" {
		c.logger.Debug("no credential spec for token",
			logger.String("token_id", te.ID),
		)
		return fmt.Errorf("cannot mint credential since no credential spec is bound to the token")
	}

	// Skip if credential manager not initialized
	if c.credentialManager == nil {
		return fmt.Errorf("credential manager not initialized")
	}

	// Validate credential spec exists before attempting to issue
	if !c.credentialManager.SpecExists(ctx, te.CredentialSpec) {
		c.logger.Warn("credential spec not found or disabled",
			logger.String("token_id", te.ID),
			logger.String("spec_name", te.CredentialSpec),
		)
		return fmt.Errorf("credential spec %q not found or disabled", te.CredentialSpec)
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

	// Issue credential using the credential manager
	// Credentials are cache-only (not persisted) - ExpirationEntry handles lease revocation
	cred, err := c.credentialManager.IssueCredential(ctx, te.ID, te.CredentialSpec, tokenTTL)
	if err != nil {
		return fmt.Errorf("failed to issue credential: %w", err)
	}

	// Inject credential into request
	req.Credential = cred

	return nil
}

// It checks X-Warden-Token header first, then falls back to Authorization: Bearer.
func extractToken(r *http.Request) string {
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

// isTransparentRequest checks if this is a transparent mode request.
// Returns true and the role name if the backend supports transparent mode,
// transparent mode is enabled, and the path is a gateway path.
// The role may be empty if no role is in the URL and no default role is configured.
func (c *Core) isTransparentRequest(req *logical.Request, backend logical.Backend) (bool, string) {
	// Check if backend supports transparent mode
	tmp, ok := backend.(logical.TransparentModeProvider)
	if !ok {
		return false, ""
	}

	// Check if transparent mode is enabled
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

	// Check if this is a gateway path (transparent mode applies to gateway requests)
	// Gateway paths are: "gateway", "gateway/...", "role/X/gateway", "role/X/gateway/..."
	if !strings.HasPrefix(relativePath, "gateway") && !strings.Contains(relativePath, "/gateway") {
		return false, ""
	}

	// Extract role from path (may return default role or empty string)
	role := tmp.GetTransparentRole(relativePath)
	return true, role
}

// handleTransparentAuth performs implicit authentication for transparent mode requests.
// It first tries to lookup the token (which may be a JWT) using the existing token store.
// If not found, it performs implicit auth via the configured auto-auth path.
// Uses singleflight to prevent duplicate token creation when concurrent requests
// arrive with the same JWT+role combination.
//
// IMPORTANT: The role is validated when reusing cached tokens. A token created for
// JWT+Role1 cannot be reused for JWT+Role2, as they may have different policies.
func (c *Core) handleTransparentAuth(ctx context.Context, req *logical.Request, backend logical.Backend, role string) error {
	// Mark request as transparent mode - credentials will be cache-only
	req.Transparent = true

	tmp := backend.(logical.TransparentModeProvider)
	autoAuthPath := tmp.GetAutoAuthPath()
	clientToken := req.ClientToken

	// Unauthenticated paths are handled earlier in handleNonLoginRequest
	// (before we even enter handleTransparentAuth), so if we get here with
	// no token, it's an error.
	if clientToken == "" {
		return fmt.Errorf("no token provided for transparent mode request")
	}

	// Check if role is available (either from URL or default_role config)
	if role == "" {
		return fmt.Errorf("transparent mode requires a role: use /role/{role}/gateway/... path or configure default_role")
	}

	// Transparent mode only supports JWT tokens
	if !strings.HasPrefix(clientToken, "eyJ") {
		return fmt.Errorf("transparent mode requires a JWT token (expected eyJ prefix)")
	}

	// Step 1: Try to lookup the token using JWT+role for proper ID computation
	te, err := c.LookupJWTTokenWithRole(ctx, clientToken, role)
	if err == nil && te != nil {
		// Token found with correct role
		req.SetTokenEntry(te)
		return nil
	}

	// Step 2: Token not found - perform implicit auth with singleflight
	// Use hash of JWT+role as the key to:
	// 1. Reduce memory overhead (JWTs can be 1-2KB+)
	// 2. Avoid storing sensitive JWT in singleflight map keys
	// 3. Ensure fast fixed-size key comparison
	jwtHash := sha256.Sum256([]byte(clientToken + ":" + role))
	singleflightKey := hex.EncodeToString(jwtHash[:])

	// Use singleflight to ensure only one implicit auth per JWT+role combination
	// This prevents duplicate token creation when concurrent requests arrive
	result, err, shared := c.transparentAuthGroup.Do(singleflightKey, func() (interface{}, error) {
		// Double-check: another goroutine may have just created the token for this role
		checkTE, lookupErr := c.LookupJWTTokenWithRole(ctx, clientToken, role)
		if lookupErr == nil && checkTE != nil {
			return checkTE, nil
		}

		// Build login request to the auto-auth path (e.g., auth/jwt/login)
		loginPath := strings.TrimSuffix(autoAuthPath, "/") + "/login"
		loginReq := &logical.Request{
			Operation:   logical.UpdateOperation,
			Path:        loginPath,
			HTTPRequest: req.HTTPRequest,
			Data: map[string]any{
				"jwt":  clientToken,
				"role": role,
			},
			ClientIP:  req.ClientIP,
			RequestID: req.RequestID,
		}

		// Perform the login request
		loginResp, _, loginErr := c.handleLoginRequest(ctx, loginReq)
		if loginErr != nil {
			return nil, loginErr
		}

		// Check for authentication errors (e.g., expired JWT, invalid token)
		if loginResp != nil && loginResp.Err != nil {
			return nil, loginResp.Err
		}

		if loginResp == nil || loginResp.Auth == nil {
			return nil, fmt.Errorf("implicit auth returned no auth data")
		}

		// Lookup the newly created token using JWT+role
		// The token was created with the JWT as its lookup value, so we can find it directly
		newTE, lookupErr := c.LookupJWTTokenWithRole(ctx, clientToken, role)
		if lookupErr != nil {
			return nil, fmt.Errorf("failed to lookup created token: %w", lookupErr)
		}

		return newTE, nil
	})

	if err != nil {
		return err
	}

	te = result.(*TokenEntry)
	_ = shared // suppress unused variable warning

	// Set the token entry on the request
	req.SetTokenEntry(te)

	return nil
}
