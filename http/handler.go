package http

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/stephnangue/warden/core"
	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/logger"
)

const (
	// defaultForwardingTimeout is the maximum time for a forwarded request to
	// the active node before timing out, when not explicitly configured.
	defaultForwardingTimeout = 60 * time.Second
)

// HandlerProperties contains configuration for the HTTP handler
type HandlerProperties struct {
	Core   *core.Core
	Logger *logger.GatedLogger

	// ClusterTLSConfigFunc returns the current cluster mTLS config for
	// forwarding requests from standby to active. When nil, forwarding
	// uses plain HTTP (backward compatible).
	ClusterTLSConfigFunc func() *tls.Config

	// ForwardingTimeout overrides the default forwarding timeout.
	// Zero means use the default (60s).
	ForwardingTimeout time.Duration
}

// Handler creates and returns the main HTTP handler for Warden.
func Handler(props *HandlerProperties) http.Handler {
	mux := http.NewServeMux()
	core := props.Core
	log := props.Logger

	// Create a shared forwarder for standby-to-active request forwarding.
	// Used both by the generic handler (pre-check) and the logical handler
	// (mid-request standby transition race).
	fwdTimeout := props.ForwardingTimeout
	if fwdTimeout == 0 {
		fwdTimeout = defaultForwardingTimeout
	}
	forwarder := newStandbyForwarder(log, props.ClusterTLSConfigFunc, fwdTimeout)
	forwarder.core = core

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
	mux.Handle("/v1/sys/", handleLogical(core, log, forwarder))

	// Logical backend endpoints - catch-all for /v1/
	// Handles provider-specific operations (e.g., /v1/aws/, /v1/provider/)
	mux.Handle("/v1/", handleLogical(core, log, forwarder))

	// Wrap with generic handler middleware
	handler := wrapGenericHandler(core, mux, log, forwarder)

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
	mu                sync.RWMutex
	proxy             *httputil.ReverseProxy
	cachedClusterAddr string // cluster address of the last-known leader; used to detect leader changes and invalidate the cached proxy
	cachedServerName  string // cert CN of the last-known leader; used to detect cert rotation across leadership terms
	logger            *logger.GatedLogger
	tlsConfigFunc     func() *tls.Config // returns cluster mTLS config; nil = plain HTTP
	core              *core.Core         // used for fresh leader lookups in ErrorHandler
	forwardingTimeout time.Duration      // max time for a forwarded request
}

func newStandbyForwarder(log *logger.GatedLogger, tlsConfigFunc func() *tls.Config, forwardingTimeout time.Duration) *standbyForwarder {
	return &standbyForwarder{logger: log, tlsConfigFunc: tlsConfigFunc, forwardingTimeout: forwardingTimeout}
}

// getProxy returns a reverse proxy targeting the current leader's cluster
// address. It caches the proxy and recreates it if the leader changes.
// redirectAddr is the leader's API address used for 307 redirects when
// the proxy encounters an error (e.g., active node unreachable).
func (f *standbyForwarder) getProxy(clusterAddr, redirectAddr string) *httputil.ReverseProxy {
	// Read the current TLS cert CN before checking the cache.
	// Each leadership term generates a new cert, so the CN changes even
	// if the cluster address stays the same (e.g., same node re-elected).
	serverName := f.currentServerName()

	f.mu.RLock()
	if f.cachedClusterAddr == clusterAddr && f.cachedServerName == serverName && f.proxy != nil {
		proxy := f.proxy
		f.mu.RUnlock()
		return proxy
	}
	f.mu.RUnlock()

	f.mu.Lock()
	defer f.mu.Unlock()

	// Double-check after acquiring write lock
	if f.cachedClusterAddr == clusterAddr && f.cachedServerName == serverName && f.proxy != nil {
		return f.proxy
	}

	target, err := url.Parse(clusterAddr)
	if err != nil {
		f.logger.Error("failed to parse cluster address for forwarding", logger.Err(err))
		return nil
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: f.forwardingTimeout,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
	}
	if f.tlsConfigFunc == nil {
		f.logger.Error("mTLS is required for request forwarding but no TLS config func was provided")
		return nil
	}
	tlsCfg := f.tlsConfigFunc()
	if tlsCfg == nil {
		f.logger.Error("mTLS is required for request forwarding but TLS config func returned nil")
		return nil
	}
	// Build a client-side TLS config from the cluster identity. We use
	// the same cert/key for mutual authentication and the same CA pool
	// for verifying the peer. All nodes share the same self-signed cert
	// (active advertises its cert+key, standbys load it). ServerName is
	// set to the cert's CN (fw-{uuid}) so standard hostname verification
	// passes without needing IP SANs.
	if serverName == "" {
		if len(tlsCfg.Certificates) > 0 && tlsCfg.Certificates[0].Leaf != nil {
			serverName = tlsCfg.Certificates[0].Leaf.Subject.CommonName
		}
	}
	transport.TLSClientConfig = &tls.Config{
		Certificates: tlsCfg.Certificates,
		RootCAs:      tlsCfg.RootCAs,
		ServerName:   serverName,
	}

	// Close idle connections from the old proxy's transport to prevent
	// leaking connections to a previous leader.
	if f.proxy != nil {
		if t, ok := f.proxy.Transport.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
	}

	f.proxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			// Do NOT rewrite req.Host — preserve the original Host header
			// so signature-sensitive protocols (e.g., AWS SigV4) that sign
			// the Host header are not broken by forwarding. req.URL.Host
			// handles connection routing; req.Host is the Host header sent
			// over the wire.

			// Standard proxy header: original Host for backend awareness.
			req.Header.Set("X-Forwarded-Host", req.Host)

			// Set forwarding headers from the direct client connection.
			// Append to X-Forwarded-For to preserve the chain from
			// upstream proxies (load balancers, etc.).
			clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
			if err != nil {
				// RemoteAddr may be a bare IP (no port) after middleware.RealIP
				if ip := net.ParseIP(req.RemoteAddr); ip != nil {
					clientIP = req.RemoteAddr
				}
			}
			if clientIP != "" {
				if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
					req.Header.Set("X-Forwarded-For", prior+", "+clientIP)
				} else {
					req.Header.Set("X-Forwarded-For", clientIP)
				}
			}
			if req.TLS != nil {
				req.Header.Set("X-Forwarded-Proto", "https")
			} else if req.Header.Get("X-Forwarded-Proto") == "" {
				req.Header.Set("X-Forwarded-Proto", "http")
			}

			// Re-inject any forwarded client certificate that the API
			// middleware extracted and stripped. The cluster listener
			// needs it as a header to pass the cert to the leader.
			if cert := listener.ForwardedClientCert(req.Context()); cert != nil {
				pemBytes := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.Raw,
				})
				req.Header.Set("X-SSL-Client-Cert", url.QueryEscape(string(pemBytes)))
			}
		},
		Transport: transport,
		// On proxy error (active node unreachable, stepping down, etc.),
		// attempt a fresh leader lookup. If the leader changed, redirect
		// to the new leader. If unchanged or unavailable, return 503
		// instead of redirecting to a potentially dead address.
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			f.logger.Warn("error forwarding request to active node",
				logger.Err(err),
				logger.String("path", r.URL.Path),
				logger.String("cluster_addr", clusterAddr))

			if isConnectionError(err) && f.core != nil {
				_, freshLeaderAddr, freshClusterAddr, leaderErr := f.core.Leader()
				if leaderErr != nil || freshLeaderAddr == "" {
					respondError(w, http.StatusServiceUnavailable, "active node unreachable and no new leader elected")
					return
				}
				if freshClusterAddr != clusterAddr || freshLeaderAddr != redirectAddr {
					// Leader changed — redirect to the new leader
					f.logger.Info("leader changed during forwarding error, redirecting to new leader",
						logger.String("new_leader", freshLeaderAddr))
					respondStandby(w, r, freshLeaderAddr)
					return
				}
				// Same leader address but unreachable — return 503
				respondError(w, http.StatusServiceUnavailable, "active node unreachable")
				return
			}

			// For non-connection errors (e.g., TLS handshake), do a fresh
			// leader lookup before redirecting to avoid stale addresses.
			if f.core != nil {
				_, freshLeaderAddr, _, leaderErr := f.core.Leader()
				if leaderErr == nil && freshLeaderAddr != "" {
					respondStandby(w, r, freshLeaderAddr)
					return
				}
			}
			respondStandby(w, r, redirectAddr)
		},
	}
	f.cachedClusterAddr = clusterAddr
	f.cachedServerName = serverName
	return f.proxy
}

// currentServerName returns the cert CN from the current cluster TLS config.
// This is cheap (pointer traversal, no crypto) and used to detect when the
// leader's TLS identity has changed across leadership terms.
func (f *standbyForwarder) currentServerName() string {
	if f.tlsConfigFunc == nil {
		return ""
	}
	tlsCfg := f.tlsConfigFunc()
	if tlsCfg == nil {
		return ""
	}
	if len(tlsCfg.Certificates) > 0 && tlsCfg.Certificates[0].Leaf != nil {
		return tlsCfg.Certificates[0].Leaf.Subject.CommonName
	}
	return ""
}

// wrapGenericHandler wraps the main handler with cross-cutting concerns:
//   - Path validation
//   - Standby request forwarding via reverse proxy with mTLS
func wrapGenericHandler(c *core.Core, handler http.Handler, log *logger.GatedLogger, forwarder *standbyForwarder) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate request path
		if !strings.HasPrefix(r.URL.Path, "/v1/") {
			respondError(w, http.StatusNotFound, "path must begin with /v1/")
			return
		}

		// On standby nodes, forward requests to the active node
		// unless the path is explicitly allowed on standby.
		if c != nil && c.Standby() && !standbyAllowedPaths[r.URL.Path] {
			forwardToActive(c, forwarder, w, r)
			return
		}

		handler.ServeHTTP(w, r)
	})
}

// forwardToActive forwards a request to the active node via the shared
// reverse proxy. Falls back to a 307 redirect if the proxy is unavailable.
func forwardToActive(c *core.Core, forwarder *standbyForwarder, w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	_, leaderAddr, clusterAddr, err := c.Leader()
	if err != nil || leaderAddr == "" {
		metrics.IncrCounter([]string{"ha", "forward", "error"}, 1)
		respondError(w, http.StatusServiceUnavailable, "node is standby and no active node found")
		return
	}

	if clusterAddr != "" {
		if proxy := forwarder.getProxy(clusterAddr, leaderAddr); proxy != nil {
			proxy.ServeHTTP(w, r)
			metrics.MeasureSince([]string{"ha", "forward", "duration"}, start)
			metrics.IncrCounter([]string{"ha", "forward", "success"}, 1)
			return
		}
	}

	metrics.IncrCounter([]string{"ha", "forward", "redirect"}, 1)
	respondStandby(w, r, leaderAddr)
}

// respondStandby issues a 307 Temporary Redirect to the active leader node.
// This allows the client to retry the request directly against the leader
func respondStandby(w http.ResponseWriter, r *http.Request, leaderAddr string) {
	target, err := url.Parse(leaderAddr)
	if err != nil {
		respondError(w, http.StatusServiceUnavailable, "invalid leader address")
		return
	}
	target.Path = r.URL.Path
	target.RawQuery = r.URL.RawQuery
	http.Redirect(w, r, target.String(), http.StatusTemporaryRedirect)
}

// isConnectionError returns true if the error indicates the remote peer is
// unreachable (connection refused, reset, closed). These errors mean the
// active node is likely dead and a redirect to its address would fail too.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		// Only match dial errors (connection refused/timeout) and
		// read/write errors (connection reset). Exclude DNS, TLS, etc.
		return netErr.Op == "dial" || netErr.Op == "read" || netErr.Op == "write"
	}
	return false
}
