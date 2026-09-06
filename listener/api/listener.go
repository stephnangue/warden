package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/stephnangue/warden/logger"
)

// Built-in HTTP server deadlines, applied when the corresponding
// ApiListenerConfig field is zero. These are the values the listener carried
// before they became configurable.
const (
	DefaultReadTimeout  = 5 * time.Second
	DefaultWriteTimeout = 10 * time.Second
	DefaultIdleTimeout  = time.Minute
)

type ApiListener struct {
	logger      *logger.GatedLogger
	server      *http.Server
	tlsDisable  bool
	tlsCertFile string
	tlsKeyFile  string
	stopped     atomic.Bool
}

type ApiListenerConfig struct {
	Logger               *logger.GatedLogger
	Address              string
	TLSCertFile          string
	TLSKeyFile           string
	TLSClientCAFile      string
	TLSDisable           bool     // default false => TLS on; requires TLSCertFile + TLSKeyFile
	TLSRequireClientCert *bool    // nil = default (true when TLSClientCAFile set)
	TrustedProxies       []string // CIDR ranges for LB cert forwarding

	// ReadTimeout, WriteTimeout and IdleTimeout override the built-in HTTP
	// server deadlines. Zero means use the default (5s read, 10s write,
	// 1m idle).
	//
	// Read and write are armed when request headers are read and are
	// absolute from that moment, so they cap the handler's whole execution
	// rather than the response write alone. Streaming and proxied paths
	// clear both per-connection via http.ResponseController — see
	// logical.ClearStreamDeadlines — so these values govern the control
	// plane, not gateway traffic.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// TLSConfig, when non-nil, is used verbatim as the server's TLS config and
	// supersedes the file-based TLS fields above (TLSCertFile/TLSKeyFile and the
	// client-CA fields are ignored). It is used to inject a dynamically-sourced
	// config — e.g. one whose GetCertificate callback resolves the serving cert
	// at handshake time from an in-memory, auto-rotating source — so no cert or
	// key is ever read from disk. When set, TLSDisable must be false. File-based
	// listeners leave this nil.
	TLSConfig *tls.Config
}

func NewApiListener(cfg ApiListenerConfig, httpHandler http.Handler) (*ApiListener, error) {
	// Validate trusted proxy CIDRs at startup to catch misconfigurations early
	if err := ValidateCIDRs(cfg.TrustedProxies); err != nil {
		return nil, fmt.Errorf("listener config: %w", err)
	}

	var handler http.Handler = httpHandler
	handler = certForwardingMiddleware(cfg.TrustedProxies)(handler)
	handler = middleware.RealIP(handler)
	handler = middleware.RequestID(handler)
	handler = middleware.Recoverer(handler)

	readTimeout := cfg.ReadTimeout
	if readTimeout == 0 {
		readTimeout = DefaultReadTimeout
	}
	writeTimeout := cfg.WriteTimeout
	if writeTimeout == 0 {
		writeTimeout = DefaultWriteTimeout
	}
	idleTimeout := cfg.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = DefaultIdleTimeout
	}

	server := &http.Server{
		Addr:         cfg.Address,
		Handler:      handler,
		IdleTimeout:  idleTimeout,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}

	switch {
	case cfg.TLSDisable:
		// Plaintext HTTP; nothing to configure.

	case cfg.TLSConfig != nil:
		// Injected dynamic TLS config (e.g. a SPIFFE-sourced config whose
		// GetCertificate resolves the serving cert at handshake time). Use it
		// verbatim and skip the file-based cert/key requirement; Start() serves
		// with empty cert/key paths, which is valid because GetCertificate is set.
		server.TLSConfig = cfg.TLSConfig

	default:
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return nil, fmt.Errorf("TLS is on by default; set tls_disable = true or provide both tls_cert_file and tls_key_file")
		}

		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		if cfg.TLSClientCAFile != "" {
			caCert, err := os.ReadFile(cfg.TLSClientCAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read tls_client_ca_file %q: %w", cfg.TLSClientCAFile, err)
			}
			caPool := x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("tls_client_ca_file %q contains no valid certificates", cfg.TLSClientCAFile)
			}
			tlsCfg.ClientCAs = caPool
			requireClientCert := cfg.TLSRequireClientCert == nil || *cfg.TLSRequireClientCert
			if requireClientCert {
				tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
			} else {
				tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
			}
		}

		server.TLSConfig = tlsCfg
	}

	return &ApiListener{
		logger:      cfg.Logger,
		server:      server,
		tlsDisable:  cfg.TLSDisable,
		tlsCertFile: cfg.TLSCertFile,
		tlsKeyFile:  cfg.TLSKeyFile,
	}, nil
}

func (l *ApiListener) Addr() string {
	return l.server.Addr
}

func (l *ApiListener) Type() string {
	return "api"
}

// Start begins the HTTP server and listens for shutdown signal
// Returns an error channel that will receive any startup errors
func (l *ApiListener) Start(ctx context.Context) error {
	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		var err error
		if l.tlsDisable {
			l.logger.Info("starting HTTP server", logger.String("address", l.server.Addr))
			err = l.server.ListenAndServe()
		} else {
			l.logger.Info("starting HTTPS server", logger.String("address", l.server.Addr))
			err = l.server.ListenAndServeTLS(l.tlsCertFile, l.tlsKeyFile)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- err
		}
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		l.logger.Info("shutdown signal received")
		return l.Stop()
	case err := <-errChan:
		l.logger.Error("HTTP Server error", logger.Err(err))
		return err
	}
}

func (l *ApiListener) Stop() error {
	// Check if already stopped, return early if so
	if !l.stopped.CompareAndSwap(false, true) {
		l.logger.Info("HTTP server already stopped, skipping")
		return nil
	}

	l.logger.Info("shutting down HTTP server")

	// Create a context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := l.server.Shutdown(ctx)
	if err != nil {
		l.logger.Error("error when shutting down the http server", logger.Err(err))
		return err
	}

	l.logger.Info("HTTP server stopped gracefully")
	return nil
}
