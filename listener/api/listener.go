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

type ApiListener struct {
	logger      *logger.GatedLogger
	server      *http.Server
	tlsEnabled  bool
	tlsCertFile string
	tlsKeyFile  string
	stopped     atomic.Bool
}

type ApiListenerConfig struct {
	Logger          *logger.GatedLogger
	Address         string
	TLSCertFile     string
	TLSKeyFile      string
	TLSClientCAFile string
	TLSEnabled      bool
}

func NewApiListener(cfg ApiListenerConfig, httpHandler http.Handler) (*ApiListener, error) {

	var handler http.Handler = httpHandler
	handler = middleware.RealIP(handler)
	handler = middleware.RequestID(handler)
	handler = middleware.Recoverer(handler)

	server := &http.Server{
		Addr:         cfg.Address,
		Handler:      handler,
		IdleTimeout:  time.Minute,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if cfg.TLSEnabled {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return nil, fmt.Errorf("tls_enabled requires both tls_cert_file and tls_key_file")
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
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		}

		server.TLSConfig = tlsCfg
	}

	return &ApiListener{
		logger:      cfg.Logger,
		server:      server,
		tlsEnabled:  cfg.TLSEnabled,
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
		if l.tlsEnabled {
			l.logger.Info("starting HTTPS server")
			err = l.server.ListenAndServeTLS(l.tlsCertFile, l.tlsKeyFile)
		} else {
			l.logger.Info("starting HTTP server")
			err = l.server.ListenAndServe()
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
