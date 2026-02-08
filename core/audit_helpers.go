package core

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
)

// buildAuditRequest converts logical.Request to audit.Request
// NOTE: Raw data passed through - format layer handles salting/omission via config
func buildAuditRequest(req *logical.Request, ns *namespace.Namespace) *audit.Request {
	if req == nil {
		return nil
	}

	auditPath := req.AuditPath
	if auditPath == "" {
		auditPath = req.Path
	}

	// Strip namespace path from mount point for audit logging.
	// The namespace is already recorded separately in namespace_id and namespace_path,
	// so mount_point should be the namespace-relative path (e.g., "aws/" not "PROD/DEV/aws/").
	mountPoint := req.MountPoint
	if ns != nil && ns.Path != "" {
		mountPoint = strings.TrimPrefix(req.MountPoint, ns.Path)
	}

	auditReq := &audit.Request{
		ID:              req.RequestID,
		Operation:       string(req.Operation),
		Path:            auditPath,
		MountPoint:      mountPoint,
		MountType:       req.MountType,
		MountClass:      req.MountClass,
		ClientIP:        req.ClientIP,
		Data:            copyMapAny(req.Data), // Raw - format layer handles
		Unauthenticated: req.Unauthenticated,
		Streamed:        req.Streamed,
		Transparent:     req.Transparent,
	}

	if req.HTTPRequest != nil {
		auditReq.Method = req.HTTPRequest.Method
		auditReq.Headers = copyHeaders(req.HTTPRequest.Header) // Raw - format layer handles
	}

	if ns != nil {
		auditReq.NamespaceID = ns.ID
		auditReq.NamespacePath = ns.Path
	}

	return auditReq
}

// buildAuditResponse converts logical.Response to audit.Response
// NOTE: Raw data passed through - format layer handles salting/omission via config
func buildAuditResponse(resp *logical.Response, req *logical.Request, cred *credential.Credential) *audit.Response {
	if resp == nil {
		return nil
	}

	// Use the status code directly from the response.
	// For streaming responses, StatusRecordingWriter captures the real status code.
	// For non-streaming responses, backends set StatusCode explicitly.
	auditResp := &audit.Response{
		StatusCode: resp.StatusCode,
		Data:       copyMapAny(resp.Data), // Raw - format layer handles
		MountClass: resp.MountClass,
		Streamed:   resp.Streamed,
		Warnings:   resp.Warnings,
	}

	if resp.Headers != nil {
		auditResp.Headers = copyHeaders(resp.Headers) // Raw - format layer handles
	}

	if cred != nil {
		auditResp.Credential = buildAuditCredential(cred)
	}

	if resp.Auth != nil {
		auditResp.AuthResult = buildAuditAuthResult(resp.Auth)
	}

	// Copy upstream URL for streaming requests (for audit tracing)
	if req != nil && req.UpstreamURL != "" {
		auditResp.UpstreamURL = req.UpstreamURL
	}

	return auditResp
}

// buildAuditAuth converts logical.Auth and logical.TokenEntry to audit.Auth
func buildAuditAuth(auth *logical.Auth, te *logical.TokenEntry) *audit.Auth {
	if auth == nil && te == nil {
		return nil
	}

	auditAuth := &audit.Auth{}

	// Populate from TokenEntry (preferred source - more complete)
	if te != nil {
		auditAuth.TokenID = te.ID
		auditAuth.TokenAccessor = te.Accessor
		auditAuth.TokenType = te.Type
		auditAuth.PrincipalID = te.PrincipalID
		auditAuth.RoleName = te.RoleName
		auditAuth.Policies = te.Policies
		auditAuth.NamespaceID = te.NamespaceID
		auditAuth.NamespacePath = te.NamespacePath
		auditAuth.CreatedByIP = te.CreatedByIP

		if !te.ExpireAt.IsZero() {
			auditAuth.ExpiresAt = te.ExpireAt.Unix()
			auditAuth.TokenTTL = int64(time.Until(te.ExpireAt).Seconds())
		}
	}

	// Override/supplement from Auth if available
	if auth != nil {
		if auth.TokenAccessor != "" {
			auditAuth.TokenAccessor = auth.TokenAccessor
		}
		if auth.TokenType != "" {
			auditAuth.TokenType = auth.TokenType
		}
		if auth.PrincipalID != "" {
			auditAuth.PrincipalID = auth.PrincipalID
		}
		if auth.RoleName != "" {
			auditAuth.RoleName = auth.RoleName
		}
		if len(auth.Policies) > 0 {
			auditAuth.Policies = auth.Policies
		}

		// Policy results
		if auth.PolicyResults != nil {
			auditAuth.PolicyResults = &audit.PolicyResults{
				Allowed: auth.PolicyResults.Allowed,
			}
			if len(auth.PolicyResults.GrantingPolicies) > 0 {
				policies := make([]string, len(auth.PolicyResults.GrantingPolicies))
				for i, gp := range auth.PolicyResults.GrantingPolicies {
					policies[i] = gp.Name
				}
				auditAuth.PolicyResults.GrantingPolicies = policies
			}
		}
	}

	return auditAuth
}

// buildAuditAuthResult converts logical.Auth (from login response) to audit.AuthResult
func buildAuditAuthResult(auth *logical.Auth) *audit.AuthResult {
	if auth == nil {
		return nil
	}

	return &audit.AuthResult{
		TokenType:      auth.TokenType,
		PrincipalID:    auth.PrincipalID,
		RoleName:       auth.RoleName,
		Policies:       auth.Policies,
		TokenTTL:       int64(auth.TokenTTL.Seconds()),
		CredentialSpec: auth.CredentialSpec,
	}
}

// buildAuditCredential converts credential.Credential to audit.Credential
// NOTE: credential.Data included raw - format layer HMAC salts via "response.credential.data"
func buildAuditCredential(cred *credential.Credential) *audit.Credential {
	if cred == nil {
		return nil
	}

	auditCred := &audit.Credential{
		CredentialID: cred.CredentialID,
		Type:         cred.Type,
		Category:     cred.Category,
		LeaseTTL:     int64(cred.LeaseTTL.Seconds()),
		LeaseID:      cred.LeaseID,
		TokenID:      cred.TokenID,
		SourceName:   cred.SourceName,
		SourceType:   cred.SourceType,
		SpecName:     cred.SpecName,
		Revocable:    cred.Revocable,
	}

	// Include credential data raw - format layer will HMAC salt it
	if cred.Data != nil {
		auditCred.Data = make(map[string]string, len(cred.Data))
		for k, v := range cred.Data {
			auditCred.Data[k] = v
		}
	}

	return auditCred
}

// copyMapAny creates a shallow copy of a map[string]any
func copyMapAny(data map[string]any) map[string]any {
	if data == nil {
		return nil
	}
	result := make(map[string]any, len(data))
	for k, v := range data {
		result[k] = v
	}
	return result
}

// copyHeaders creates a copy of HTTP headers
func copyHeaders(headers http.Header) map[string][]string {
	if headers == nil {
		return nil
	}
	result := make(map[string][]string, len(headers))
	for k, v := range headers {
		if v != nil {
			copied := make([]string, len(v))
			copy(copied, v)
			result[k] = copied
		}
	}
	return result
}

// buildRequestAuditEntry creates an audit.LogEntry for a request
func (c *Core) buildRequestAuditEntry(
	ctx context.Context,
	req *logical.Request,
	auth *logical.Auth,
	te *logical.TokenEntry,
	outerErr error,
) *audit.LogEntry {
	ns, _ := namespace.FromContext(ctx)

	entry := &audit.LogEntry{
		Type:      string(audit.EntryTypeRequest),
		Timestamp: time.Now().UTC(),
		Request:   buildAuditRequest(req, ns),
		Auth:      buildAuditAuth(auth, te),
	}

	if outerErr != nil {
		entry.Error = outerErr.Error()
	}

	return entry
}

// buildResponseAuditEntry creates an audit.LogEntry for a response
func (c *Core) buildResponseAuditEntry(
	ctx context.Context,
	req *logical.Request,
	resp *logical.Response,
	auth *logical.Auth,
	te *logical.TokenEntry,
	outerErr error,
) *audit.LogEntry {
	ns, _ := namespace.FromContext(ctx)

	var cred *credential.Credential
	if req != nil {
		cred = req.Credential
	}

	entry := &audit.LogEntry{
		Type:      string(audit.EntryTypeResponse),
		Timestamp: time.Now().UTC(),
		Request:   buildAuditRequest(req, ns),
		Auth:      buildAuditAuth(auth, te),
		Response:  buildAuditResponse(resp, req, cred),
	}

	// Capture error from multiple sources:
	// 1. outerErr - errors from request processing (e.g., routing errors)
	// 2. resp.Err - errors from backend handlers (e.g., validation errors)
	if outerErr != nil {
		entry.Error = outerErr.Error()
	} else if resp != nil && resp.Err != nil {
		entry.Error = resp.Err.Error()
	}

	return entry
}
