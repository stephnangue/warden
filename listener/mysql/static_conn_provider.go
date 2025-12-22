package mysql

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/cred"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/target"
)

type StaticConnProvider struct {
	fetcher *cred.CredentialFetcher
	conns   []*BackendConn
	logger  *logger.GatedLogger
	target  target.Target
}

func NewStaticConnProvider(role *authorize.Role,
	credSource *cred.CredSource,
	target target.Target,
	logger *logger.GatedLogger) (*StaticConnProvider, error) {

	fetcher, err := cred.NewCredentialFetcher(role, credSource, logger)
	if err != nil {
		return nil, err
	}

	provider := &StaticConnProvider{
		fetcher: fetcher,
		conns:   make([]*BackendConn, 0),
		logger:  logger,
		target:  target,
	}

	return provider, nil
}

func (s *StaticConnProvider) GetConn(ctx context.Context) (*BackendConn, error) {

	var conn *BackendConn

	// search for an unused connection
	for _, c := range s.conns {
		c.mu.Lock()
		refCount := c.refCount
		c.mu.Unlock()

		// only return the first conn that is unused
		if refCount == 0 {
			conn = c
			break
		}
	}
	var err error
	// if no connection exist create one
	if conn == nil {
		conn, err = s.createConn(ctx)
		if err != nil {
			return nil, err
		}
		s.conns = append(s.conns, conn)
		s.logger.Trace("new connection created", logger.Int("total_conn", len(s.conns)))
	}

	conn.mu.Lock()
	conn.refCount++
	conn.mu.Unlock()

	return conn, nil
}

func (s *StaticConnProvider) Stop() {
	for _, conn := range s.conns {
		conn.Quit()
	}
}

func (s *StaticConnProvider) fetchCredential(ctx context.Context) (*cred.DatabaseUserpass, bool, error) {
	credential, ok, err := s.fetcher.FetchCredential(ctx)
	if err != nil {
		return nil, ok, err
	}
	if !ok {
		return nil, ok, nil
	}
	switch credential.Type {
	case "database_userpass":
		return &cred.DatabaseUserpass{
			Username: credential.Data["username"],
			Password: credential.Data["password"],
			Database: credential.Data["database"],
		}, true, nil
	default:
		return nil, false, fmt.Errorf("unsupported database credential type : %s", credential.Type)
	}
}

func (s *StaticConnProvider) createConn(ctx context.Context) (*BackendConn, error) {
	cred, ok, err := s.fetchCredential(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("no credential found")
	}

	addr := fmt.Sprintf("%s:%s", s.target.GetHostname(), s.target.GetPort())

	var tlsConfig *tls.Config
	if s.target.IsMtlsEnabled() {
		tlsConfig = client.NewClientTLSConfig([]byte(s.target.GetCACert()), []byte(s.target.GetClientCert()), []byte(s.target.GetClientKey()), false, s.target.GetHostname())
	}
	var conn *client.Conn
	if tlsConfig != nil {
		conn, err = client.Connect(addr, cred.Username, cred.Password, cred.Database, func(c *client.Conn) error {
			c.SetTLSConfig(tlsConfig)
			return nil
		})
	} else {
		conn, err = client.Connect(addr, cred.Username, cred.Password, cred.Database, func(c *client.Conn) error {
			c.UseSSL(true)
			return nil
		})
	}
	if err != nil {
		return nil, err
	}

	backend := &BackendConn{
		Conn:     conn,
		refCount: 0,
	}

	return backend, nil
}
