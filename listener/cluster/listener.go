package cluster

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/logger"
)

// ClusterListener is a dedicated listener for inter-node cluster
// communication. It always enforces mTLS using dynamically generated
// certificates from the Core's cluster identity.
type ClusterListener struct {
	logger        *logger.GatedLogger
	server        *http.Server
	address       string
	tlsConfigFunc func() *tls.Config
	stopped       atomic.Bool
}

// ClusterListenerConfig holds configuration for the cluster listener.
type ClusterListenerConfig struct {
	Logger  *logger.GatedLogger
	Address string
	Handler http.Handler

	// TLSConfigFunc returns the current cluster TLS config. It is called
	// at handshake time so that leadership transitions (which generate
	// new certs) take effect without restarting the listener.
	TLSConfigFunc func() *tls.Config

	// ReadTimeout and WriteTimeout override the defaults for the HTTP server.
	// Zero means use the built-in defaults (30s read, 60s write).
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// NewClusterListener creates a new cluster listener that serves the
// given HTTP handler with mTLS enforced via the provided TLS config
// function.
func NewClusterListener(cfg ClusterListenerConfig) (*ClusterListener, error) {
	if cfg.TLSConfigFunc == nil {
		return nil, errors.New("cluster listener requires a TLS config function")
	}

	readTimeout := cfg.ReadTimeout
	if readTimeout == 0 {
		readTimeout = 30 * time.Second
	}
	writeTimeout := cfg.WriteTimeout
	if writeTimeout == 0 {
		writeTimeout = 60 * time.Second
	}

	// Wrap the handler to re-parse any cert forwarding headers from the
	// original request. ParseForwardedCert re-extracts the original client
	// cert from headers (X-SSL-Client-Cert / XFCC) that the standby's
	// reverse proxy preserved. This is safe because the cluster listener
	// enforces mTLS — only authenticated cluster nodes can send requests here.
	clusterHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if cert := listener.ParseForwardedCert(r); cert != nil {
			ctx = listener.WithForwardedClientCert(ctx, cert)
		}
		cfg.Handler.ServeHTTP(w, r.WithContext(ctx))
	})

	server := &http.Server{
		Handler:      clusterHandler,
		IdleTimeout:  time.Minute,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Use GetConfigForClient to dynamically return the TLS config
			// at each handshake. This allows cert rotation on leadership
			// transitions without restarting the listener.
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				tlsCfg := cfg.TLSConfigFunc()
				if tlsCfg == nil {
					return nil, errors.New("cluster TLS identity not yet available")
				}
				if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
					return nil, errors.New("cluster TLS config must enforce mutual TLS")
				}
				if len(tlsCfg.Certificates) == 0 {
					return nil, errors.New("cluster TLS config has no certificates")
				}
				if tlsCfg.ClientCAs == nil {
					return nil, errors.New("cluster TLS config missing client CA pool")
				}
				return tlsCfg, nil
			},
		},
	}

	return &ClusterListener{
		logger:        cfg.Logger,
		server:        server,
		address:       cfg.Address,
		tlsConfigFunc: cfg.TLSConfigFunc,
	}, nil
}

func (l *ClusterListener) Addr() string {
	return l.address
}

func (l *ClusterListener) Type() string {
	return "cluster"
}

// Start begins the cluster listener with mTLS.
func (l *ClusterListener) Start(ctx context.Context) error {
	l.logger.Info("starting cluster listener (mTLS)")

	ln, err := net.Listen("tcp", l.address)
	if err != nil {
		return err
	}

	// Wrap the raw TCP listener with TLS. The TLS config uses
	// GetConfigForClient for dynamic cert lookup at each handshake.
	tlsListener := tls.NewListener(ln, l.server.TLSConfig)

	errChan := make(chan error, 1)
	go func() {
		err := l.server.Serve(tlsListener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- err
		}
	}()

	select {
	case <-ctx.Done():
		l.logger.Info("cluster listener shutdown signal received")
		return l.Stop()
	case err := <-errChan:
		l.logger.Error("cluster listener error", logger.Err(err))
		return err
	}
}

func (l *ClusterListener) Stop() error {
	if !l.stopped.CompareAndSwap(false, true) {
		l.logger.Info("cluster listener already stopped, skipping")
		return nil
	}

	l.logger.Info("shutting down cluster listener")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := l.server.Shutdown(ctx)
	if err != nil {
		l.logger.Error("error shutting down cluster listener", logger.Err(err))
		return err
	}

	l.logger.Info("cluster listener stopped gracefully")
	return nil
}
