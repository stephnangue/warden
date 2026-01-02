package core

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/middleware"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/pathmanager"
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

// ServeHTTP makes the Core an http.Handler
func (c *Core) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ok := c.auditRequest(req)
	if !ok {
		c.logger.Warn("No audit device processed the request", logger.String("request_id", middleware.GetReqID(req.Context())))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Try pre-init handler first (handles bootstrap operations like /sys/init)
	// These operations must work even before activeContext is set
	if c.preInitHandler != nil {
		handled, err := c.preInitHandler.TryHandle(w, req)
		if err != nil {
			c.logger.Error("pre-init handler error",
				logger.Err(err),
				logger.String("path", req.URL.Path),
				logger.String("method", req.Method),
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if handled {
			// Request was handled by pre-init handler, return early
			return
		}
	}

	// Check if the core is sealed - all non-bootstrap paths require unsealed state
	if c.Sealed() {
		http.Error(w, "Warden is sealed", http.StatusServiceUnavailable)
		return
	}

	if c.activeContext == nil || c.activeContext.Err() != nil {
		if c.standby.Load() {
			http.Error(w, "Standby node, please forward to active", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "Server context canceled", http.StatusServiceUnavailable)
		return
	}

	// Extract namespace header from HTTP request
	nsHeader := req.Header.Get("X-Warden-Namespace")

	// Sanitize the request path
	requestPath := strings.TrimPrefix(req.URL.Path, "/v1/")
	requestPath = strings.TrimSuffix(requestPath, "/")

	// Resolve namespace from header and request path
	// /v1/ns1/sys/namespaces/test1 -> ns1/ and sys/namespaces/test1
	// /v1/sys/namespaces/test1 with X-Warden-Namespace=ns1 -> ns1/ and sys/namespaces/test1
	ns, trimmedPath := c.namespaceStore.ResolveNamespaceFromRequest(nsHeader, requestPath)

	if ns == nil {
		if trimmedPath != "" {
			c.logger.Warn("namespace resolution failed",
				logger.String("trimmed_path", trimmedPath),
				logger.String("namespace_header", nsHeader),
				logger.String("request_path", req.URL.Path))
		}
		http.Error(w, "namespace not found", http.StatusNotFound)
		return
	}

	if ns.ID != namespace.RootNamespaceID {
		// verify whether the namespace is either directly or inherently locked
		// lockedNS := c.namespaceStore.GetLockingNamespace(ns)
		// if lockedNS != nil && req.Operation != logical.RevokeOperation && req.Operation != logical.RollbackOperation {
		// 	switch req.Path {
		// 	case "sys/namespaces/api-lock/unlock":
		// 	default:
		// 		return logical.ErrorResponse("API access to this namespace has been locked by an administrator - %q must be unlocked to gain access.", lockedNS.Path), logical.ErrLockedNamespace
		// 	}
		// }

		if strings.HasPrefix(req.URL.Path, "sys/") &&
			restrictedSysAPIs.HasPathSegments(req.URL.Path[len("sys/"):]) {
			http.Error(w, "operation unavailable in namespaces", http.StatusBadRequest)
			return
		}
	}

	// Extract the ip address and add it in the request context
	clientIP := req.Header.Get("X-Real-IP")
	if clientIP == "" {
		clientIP = req.RemoteAddr
	}
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}
	ctx := namespace.ContextWithNamespace(req.Context(), ns)
	ctx = context.WithValue(ctx, "client_ip", clientIP)
	req = req.WithContext(ctx)

	// Store the original request path in the request context
	originalPath := req.URL.Path
	ctx = req.Context()
	ctx = context.WithValue(ctx, logical.OriginalPath, originalPath)
	req = req.WithContext(ctx)

	// Set the request path to the path relative to the namespace
	req.URL.Path = trimmedPath
	req.URL.RawPath = ""

	// Create active context that cancels when either activeContext or HTTP request is done
	activeCtx, cancel := context.WithCancel(c.activeContext)
	go func(ctx context.Context, httpCtx context.Context) {
		select {
		case <-ctx.Done():
		case <-httpCtx.Done():
			cancel()
		}
	}(activeCtx, req.Context())

	c.router.Route(w, req)
}
