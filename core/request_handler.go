package core

import (
	"bytes"
	"context"
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
	if !unauth || (unauth && req.ClientToken != "" ) {
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
		ClientToken: req.ClientToken,
		TokenAccessor:    req.ClientTokenAccessor,
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
				errors.Is(err, ErrAuthDeadlineViolated) ||
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

	// Update the HTTP request with the new context if present
	if req.HTTPRequest != nil {
		reqCtx := namespace.ContextWithNamespace(req.HTTPRequest.Context(), ns)
		req.HTTPRequest = req.HTTPRequest.WithContext(reqCtx)
	}

	// extract the clientToken if provided
	matchingBackend := c.router.MatchingBackend(ctx, req.Path)
	if matchingBackend == nil {
		c.logger.Warn("no backend mounted at path",
			logger.String("full_req_path", req.HTTPRequest.URL.Path),
			logger.String("relative_req_path", req.Path),
			logger.String("namespace", ns.Path),
		)
		return logical.ErrorResponse(logical.ErrNotFoundf("no handler for path %q", req.Path)), nil
	}
	
	req.ClientToken = matchingBackend.ExtractToken(req.HTTPRequest)

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

	//var auth *logical.Auth
	if c.isLoginRequest(ctx, req) {
		resp, _, err = c.handleLoginRequest(ctx, req)
	} else {
		resp, _, err = c.handleNonLoginRequest(ctx, req)
	}

	// Create an audit trail of the response
	// logInput := &logical.LogInput{
	// 	Auth:                auth,
	// 	Request:             req,
	// 	Response:            auditResp,
	// 	OuterErr:            err,
	// }
	// if auditErr := c.auditBroker.LogResponse(ctx, logInput, c.auditedHeaders); auditErr != nil {
	// 	c.logger.Error("failed to audit response", "request_path", req.Path, "error", auditErr)
	// 	return nil, ErrInternalError
	// }

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

		// logInput := &logical.LogInput{
		// 	Auth:               auth,
		// 	Request:            req,
		// 	OuterErr:           ctErr,
		// 	NonHMACReqDataKeys: nonHMACReqDataKeys,
		// }
		// if err := c.auditBroker.LogRequest(ctx, logInput, c.auditedHeaders); err != nil {
		// 	c.logger.Error("failed to audit request", "path", req.Path, "error", err)
		// 	return nil, nil, ErrInternalError
		// }

		if errType != nil {
			retErr = multierror.Append(retErr, errType)
		}
		if ctErr == ErrInternalError {
			return nil, auth, retErr
		}
		return logical.ErrorResponse(logical.ErrInternal(ctErr.Error())), auth, retErr
	}

	switch req.Path {
	default:
		// Create an audit trail of the request. Attach auth if it was returned,
		// e.g. if a token was provided.
		// logInput := &logical.LogInput{
		// 	Auth:               auth,
		// 	Request:            req,
		// 	NonHMACReqDataKeys: nonHMACReqDataKeys,
		// }
		// if err := c.auditBroker.LogRequest(ctx, logInput, c.auditedHeaders); err != nil {
		// 	c.logger.Error("failed to audit request", "path", req.Path, "error", err)
		// 	return nil, nil, ErrInternalError
		// }
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
		AuthDeadline:   now.Add(auth.AuthDeadline),
		ExpireAt:       now.Add(auth.TokenTTL),
		CredentialSpec: auth.CredentialSpec,
		Policies:       auth.Policies,
		ClientIP:       auth.ClientIP,
	}

	tokenValue, err := c.tokenStore.GenerateToken(ctx, auth.TokenType, &authData)

	if err != nil {
		// error when creating token
		c.logger.Error("Failed to generate token", logger.String("token_type", auth.TokenType), logger.Any("auth_data", authData))
		return logical.ErrorResponse(logical.ErrInternal("failed to generate token")), ErrInternalError
	}

	data := map[string]any{
		"token_type": tokenValue.Type,
		"expire_at": tokenValue.ExpireAt,
		"bound_ip": tokenValue.CreatedByIP,
		"token_id": tokenValue.ID,
		"token_assessor": tokenValue.Accessor,
		"auth_deadline": tokenValue.AuthDeadline,
		"namespace": tokenValue.NamespacePath,
		"role": tokenValue.RoleName,
		"data": tokenValue.Data,
		"policies": tokenValue.Policies,
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
	}

	// Parse request body before CheckToken since req.Data may be used during policy evaluation
	if !c.isStreamingRequest(ctx, req.Path) {
		if err := c.parseRequestBody(req); err != nil {
			return logical.ErrorResponse(logical.ErrBadRequest(err.Error())), nil, err
		}
	} else {
		req.Streamed = true
	}

	// Validate the token (non-login requests require authentication)
	auth, _, te, ctErr := c.CheckToken(ctx, req, false)
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

		// logInput := &logical.LogInput{
		// 	Auth:               auth,
		// 	Request:            req,
		// 	OuterErr:           ctErr,
		// 	NonHMACReqDataKeys: nonHMACReqDataKeys,
		// }
		// if err := c.auditBroker.LogRequest(ctx, logInput, c.auditedHeaders); err != nil {
		// 	c.logger.Error("failed to audit request", "path", req.Path, "error", err)
		// }

		if errwrap.Contains(retErr, ErrInternalError.Error()) {
			return nil, auth, retErr
		}
		return logical.ErrorResponse(ctErr), auth, retErr
	}

	// // Create an audit trail of the request
	// logInput := &logical.LogInput{
	// 	Auth:               auth,
	// 	Request:            req,
	// 	NonHMACReqDataKeys: nonHMACReqDataKeys,
	// }
	// if err := c.auditBroker.LogRequest(ctx, logInput, c.auditedHeaders); err != nil {
	// 	c.logger.Error("failed to audit request", "path", req.Path, "error", err)
	// 	retErr = multierror.Append(retErr, ErrInternalError)
	// 	return nil, auth, retErr
	// }

	// For streaming requests, mint credentials and mark as streamed
	if req.Streamed {
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
		c.logger.Debug("no credential spec for token, skipping credential minting",
			logger.String("token_id", te.ID),
		)
		return fmt.Errorf("cannot mint credential since no credential spec is bound to the token")
	}

	// Skip if credential manager not initialized
	if c.credentialManager == nil {
		return fmt.Errorf("credential manager not initialized")
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
	cred, err := c.credentialManager.IssueCredential(ctx, te.ID, te.CredentialSpec, tokenTTL)
	if err != nil {
		return fmt.Errorf("failed to issue credential: %w", err)
	}

	// Inject credential into request
	req.Credential = cred

	c.logger.Debug("credential minted for streaming request",
		logger.String("token_id", te.ID),
		logger.String("spec", te.CredentialSpec),
		logger.String("cred_type", cred.Type),
	)

	return nil
}


