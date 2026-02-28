package http

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/logger"
)

const (
	// forwardingTimeout is the maximum time for a forwarded request to
	// the active node before timing out.
	forwardingTimeout = 60 * time.Second
)

// HandlerProperties contains configuration for the HTTP handler
type HandlerProperties struct {
	Core   *core.Core
	Logger *logger.GatedLogger
}

// Handler creates and returns the main HTTP handler for Warden.
func Handler(props *HandlerProperties) http.Handler {
	mux := http.NewServeMux()
	core := props.Core
	log := props.Logger

	// HA endpoints — must work on standby and sealed nodes.
	// Register before the /v1/sys/ catch-all.
	mux.Handle("/v1/sys/health", handleSysHealth(core, log))
	mux.Handle("/v1/sys/ready", handleSysReady(core, log))
	mux.Handle("/v1/sys/leader", handleSysLeader(core, log))
	mux.Handle("/v1/sys/step-down", handleSysStepDown(core, log))
	mux.Handle("/v1/sys/seal-status", handleSysSealStatus(core, log))

	// System init endpoint - handles initialization before system is ready
	mux.Handle("/v1/sys/init", handleSysInit(core, log))

	// System backend endpoints - catch-all for /v1/sys/
	// Handles providers, auth, namespaces, credentials, etc.
	mux.Handle("/v1/sys/", handleLogical(core, log))

	// Logical backend endpoints - catch-all for /v1/
	// Handles provider-specific operations (e.g., /v1/aws/, /v1/provider/)
	mux.Handle("/v1/", handleLogical(core, log))

	// Wrap with generic handler middleware
	handler := wrapGenericHandler(core, mux, log)

	return handler
}

// standbyAllowedPaths are paths that can be served directly by standby nodes
// without forwarding to the active node.
var standbyAllowedPaths = map[string]bool{
	"/v1/sys/health":      true,
	"/v1/sys/ready":       true,
	"/v1/sys/leader":      true,
	"/v1/sys/seal-status": true,
	"/v1/sys/init":        true,
}

// standbyForwarder manages reverse proxy forwarding from standby to active.
type standbyForwarder struct {
	mu        sync.RWMutex
	proxy     *httputil.ReverseProxy
	leaderURL string
	logger    *logger.GatedLogger
}

func newStandbyForwarder(log *logger.GatedLogger) *standbyForwarder {
	return &standbyForwarder{logger: log}
}

// getProxy returns a reverse proxy targeting the current leader.
// It caches the proxy and recreates it if the leader changes.
func (f *standbyForwarder) getProxy(leaderAddr string) *httputil.ReverseProxy {
	f.mu.RLock()
	if f.leaderURL == leaderAddr && f.proxy != nil {
		proxy := f.proxy
		f.mu.RUnlock()
		return proxy
	}
	f.mu.RUnlock()

	f.mu.Lock()
	defer f.mu.Unlock()

	// Double-check after acquiring write lock
	if f.leaderURL == leaderAddr && f.proxy != nil {
		return f.proxy
	}

	target, err := url.Parse(leaderAddr)
	if err != nil {
		f.logger.Error("failed to parse leader address for forwarding", logger.Err(err))
		return nil
	}

	transport := &http.Transport{
		ResponseHeaderTimeout: forwardingTimeout,
	}

	f.proxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host

			// Set standard forwarding headers for observability
			if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
				if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
					clientIP = prior + ", " + clientIP
				}
				req.Header.Set("X-Forwarded-For", clientIP)
			}
			if req.TLS != nil {
				req.Header.Set("X-Forwarded-Proto", "https")
			} else if req.Header.Get("X-Forwarded-Proto") == "" {
				req.Header.Set("X-Forwarded-Proto", "http")
			}
		},
		Transport: transport,
		// On proxy error (active node unreachable, stepping down, etc.),
		// fall back to a 307 redirect so the client can retry directly.
		// This matches OpenBao/Vault behavior during leader transitions.
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			f.logger.Warn("error forwarding request to active node, falling back to redirect",
				logger.Err(err),
				logger.String("path", r.URL.Path),
				logger.String("leader", leaderAddr))
			respondStandby(w, r, leaderAddr)
		},
	}
	f.leaderURL = leaderAddr
	return f.proxy
}

// invalidate clears the cached proxy so the next call to getProxy
// will create a fresh one with an updated leader address.
func (f *standbyForwarder) invalidate() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proxy = nil
	f.leaderURL = ""
}

// wrapGenericHandler wraps the main handler with cross-cutting concerns:
//   - Path validation
//   - Standby request forwarding via reverse proxy
func wrapGenericHandler(c *core.Core, handler http.Handler, log *logger.GatedLogger) http.Handler {
	forwarder := newStandbyForwarder(log)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate request path
		if !strings.HasPrefix(r.URL.Path, "/v1/") {
			respondError(w, http.StatusNotFound, "path must begin with /v1/")
			return
		}

		// On standby nodes, forward requests to the active node
		// unless the path is explicitly allowed on standby.
		if c != nil && c.Standby() && !standbyAllowedPaths[r.URL.Path] {
			isLeader, leaderAddr, _, err := c.Leader()
			if err != nil || (!isLeader && leaderAddr == "") {
				respondError(w, http.StatusServiceUnavailable, "node is standby and no active node found")
				return
			}

			proxy := forwarder.getProxy(leaderAddr)
			if proxy == nil {
				// Can't create proxy — fall back to 307 redirect
				respondStandby(w, r, leaderAddr)
				return
			}

			proxy.ServeHTTP(w, r)
			return
		}

		handler.ServeHTTP(w, r)
	})
}

// respondStandby issues a 307 Temporary Redirect to the active leader node.
// This allows the client to retry the request directly against the leader,
// matching OpenBao/Vault behavior during leader transitions.
func respondStandby(w http.ResponseWriter, r *http.Request, leaderAddr string) {
	redirectURL := leaderAddr + r.URL.RequestURI()
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}
