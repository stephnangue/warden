package api

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/middleware"
	"github.com/stephnangue/warden/logger"
)

type ApiListener struct {
	logger  *logger.GatedLogger
	server  *http.Server
	stopped atomic.Bool
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

	return &ApiListener{
		logger: cfg.Logger,
		server: server,
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
	l.logger.Info("starting HTTP server")

	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		err := l.server.ListenAndServe()
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
