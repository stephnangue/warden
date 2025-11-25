package mysql

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/pires/go-proxyproto"
	"github.com/stephnangue/warden/auth/token"
	"github.com/stephnangue/warden/cred"
	"github.com/stephnangue/warden/listener/mysql/server"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/role"
	"github.com/stephnangue/warden/target"
)


type MysqlListener struct {
	// This is the main listener socket.
	listener     net.Listener
	logger       logger.Logger
	server       *server.Server
	roles        *role.RoleRegistry
	credSources  *cred.CredSourceRegistry
	targets      *target.TargetRegistry
	wg           sync.WaitGroup
	tokenStore   token.TokenAccess
	stopped      atomic.Bool
}

type MysqlListenerConfig struct {
	// Protocol-Address pair and Listener are mutually exclusive parameters
	Protocol            string
	Address             string
	Listener            net.Listener
	// ProxyProtocolpair and Listener are mutually exclusive parameters
	ProxyProtocol       bool

	Roles               *role.RoleRegistry
	CredSources         *cred.CredSourceRegistry
	Targets             *target.TargetRegistry
	
	Logger              logger.Logger

	TLSCertFile       	string
	TLSKeyFile        	string
	TLSClientCAFile   	string
	TLSEnabled       	bool 

	TokenStore          token.TokenAccess
}

// NewMysqlListener creates new listener using provided config. There are
// no default values for config, so caller should ensure its correctness.
func NewMysqlListener(cfg MysqlListenerConfig) (*MysqlListener, error) {
	var l net.Listener
	if cfg.Listener != nil {
		l = cfg.Listener
	} else {
		var listener net.Listener
		var err error
		if cfg.ProxyProtocol {
			listener, err = net.Listen(cfg.Protocol, cfg.Address)
			proxyListener := &proxyproto.Listener{Listener: listener}
			listener = proxyListener
		} else {
			listener, err = net.Listen(cfg.Protocol, cfg.Address)
		}
		
		if err != nil {
			return nil, err
		}
		l = listener
	}

	var tlsConf *tls.Config
	var cert, privKey, caCert, pubKey []byte
	var err error
	if cfg.TLSEnabled {
		cert, privKey, caCert, pubKey, err = loadCertificatesAndKey(cfg.TLSCertFile, 
			cfg.TLSKeyFile, 
			cfg.TLSClientCAFile)
		if err != nil {
			return nil, err
		}
		tlsConf = server.NewServerTLSConfig(caCert, cert, privKey, tls.VerifyClientCertIfGiven)
	}

	server := server.NewServer("8.0.11",
		mysql.DEFAULT_COLLATION_ID,
		mysql.AUTH_NATIVE_PASSWORD,
		pubKey,
		tlsConf)

	return &MysqlListener{
		listener:            l,
		logger:              cfg.Logger,
		server:              server,
		roles:               cfg.Roles,
		credSources:         cfg.CredSources,
		targets:             cfg.Targets,
		tokenStore:          cfg.TokenStore,
	}, nil
}

// Addr returns the listener address.
func (l *MysqlListener) Addr() string {
	return l.listener.Addr().String()
}

func (l *MysqlListener) Type() string {
	return "mysql"
}

func (l *MysqlListener) Start(ctx context.Context) error {
	l.logger.Info("Starting MySQL listener")

	// Channel to signal accept loop to stop
	done := make(chan struct{})
	errChan := make(chan error, 1)

	go func() {
		for {
			select {
			case <-done:
				return
			default:
				conn, err := l.listener.Accept()
				if err != nil {
					select {
					case <-done:
						// Listener was closed due to shutdown, this is expected
						return
					default:
						l.logger.Error("error when accepting the connection", logger.Err(err))
						errChan <- err
						return
					}
				}

				l.wg.Add(1)
				go func() {
					defer l.wg.Done()
					l.handle(conn)
				}()
			}
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		l.logger.Info("Shutdown signal received")
		close(done)
		return l.Stop()
	case err := <-errChan:
		close(done)
		l.logger.Error("MySQL listener error", logger.Err(err))
		return err
	}
}

// handle is called in a go routine for each client connection.
func (l *MysqlListener) handle(c net.Conn) {

	provider := NewCredentialProvider(l.tokenStore)

	authResolver := NewAuthResolver(l.tokenStore)

	handler, err := NewMysqlHandler(l.roles, l.credSources, l.targets, l.logger.WithSystem("mysql.handler"))
	if err != nil {
		l.logger.Error("error when creating mysql handler", logger.Err(err))
		return
	}

	conn, err := l.server.NewConn(c, authResolver, provider, handler)
	if err != nil {
		l.logger.Error("error when creating server connection", logger.Err(err))
		return
	}

	// Close the connection in any case.
	defer func() {
		if conn != nil && !conn.Closed() {
			conn.Close()
		}
	}()

	// as long as the client keeps sending commands, keep handling them
	for {
		if err := conn.HandleCommand(); err != nil {
			l.logger.Error("connection closed gracefully or an error occured", logger.Err(err))
			return
		}
	}	
}

// Stop closes the listener and waits for all active connections to complete
func (l *MysqlListener) Stop() error {
	// Check if already stopped, return early if so
	if !l.stopped.CompareAndSwap(false, true) {
		l.logger.Info("MySQL listener already stopped, skipping")
		return nil
	}

	l.logger.Info("Shutting down MySQL listener")
	// Close the listener to stop accepting new connections
	if err := l.listener.Close(); err != nil {
		l.logger.Error("error closing listener", logger.Err(err))
	}

	// Wait for all active connections to finish
	l.wg.Wait()

	l.logger.Info("MySQL listener stopped gracefully")
	return nil
}

func loadCertificatesAndKey(certPath, keyPath, caCertPath string) ([]byte, []byte, []byte, []byte, error) {
    certBytes, err := os.ReadFile(certPath)
    if err != nil {
        return nil, nil, nil, nil, fmt.Errorf("failed to read certificate: %w", err)
    }

    // Decode PEM block
    block, _ := pem.Decode(certBytes)
    if block == nil {
        return nil, nil, nil, nil, fmt.Errorf("certificate is not valid PEM format")
    }

    // Parse certificate
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return nil, nil, nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
    }

    // Marshal public key to DER format
    publicKeyByte, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
    if err != nil {
        return nil, nil, nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
    }

    keyBytes, err := os.ReadFile(keyPath)
    if err != nil {
        return nil, nil, nil, nil, fmt.Errorf("failed to read private key: %w", err)
    }

    if !isValidPEM(keyBytes) {
        return nil, nil, nil, nil, fmt.Errorf("private key is not valid PEM format")
    }

    clientCaCertBytes, err := os.ReadFile(caCertPath)
    if err != nil {
        return nil, nil, nil, nil, fmt.Errorf("failed to read client CA certificate: %w", err)
    }

    if !isValidPEM(clientCaCertBytes) {
        return nil, nil, nil, nil, fmt.Errorf("client CA certificate is not valid PEM format")
    }

	return certBytes, keyBytes, clientCaCertBytes, publicKeyByte, nil
}

func isValidPEM(data []byte) bool {
    block, _ := pem.Decode(data)
    return block != nil
}

