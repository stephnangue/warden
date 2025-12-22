package mysql

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/cred"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/target"
)

// DynamicConnProvider creates conns with the same TTL as the dynamic database lease it fetches from Vault.
// At 80% of the TTL the conns are marked for deletion and then a new conn is created to replace the one marked for deletion or deleted
// then, the conns marked for deletion are deleted when no query is using them
type DynamicConnProvider struct {
	fetcher *cred.CredentialFetcher

	mu    sync.RWMutex
	conns []*BackendConn

	logger *logger.GatedLogger

	target target.Target

	// the conn provider uses stopChan to stop lifecycleRoutine
	stopChan chan struct{}
}

func NewDynamicConnProvider(role *authorize.Role, credSource *cred.CredSource, target target.Target, logger *logger.GatedLogger) (*DynamicConnProvider, error) {

	fetcher, err := cred.NewCredentialFetcher(role, credSource, logger)
	if err != nil {
		return nil, err
	}

	store := &DynamicConnProvider{
		fetcher:  fetcher,
		conns:    make([]*BackendConn, 0),
		stopChan: make(chan struct{}),
		logger:   logger,
		target:   target,
	}

	go store.lifecycleRoutine()
	return store, nil
}

func (s *DynamicConnProvider) createConn(ctx context.Context) (*BackendConn, error) {
	cred, ok, err := s.fetchCredential(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("no credential found")
	}

	s.logger.Trace("new dynamic cred fetches", logger.String("lease_ttl", cred.LeaseTTL))

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

	ttl, err := time.ParseDuration(cred.LeaseTTL + "s")
	if err != nil {
		return nil, err
	}

	now := time.Now()
	backend := &BackendConn{
		Conn:      conn,
		createdAt: now,
		expiresAt: now.Add(ttl),         // the new create conn has the same TTL as the database lease
		markedAt:  now.Add(ttl * 4 / 5), // mark for deletion at 80% of the TTL
		deleteAt:  now.Add(ttl * 4 / 5), // delete at 80% of the TTL
		isMarked:  false,
		refCount:  0,
	}

	return backend, nil
}

func (s *DynamicConnProvider) GetConn(ctx context.Context) (*BackendConn, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var conn *BackendConn
	var maxTTL time.Duration = -1

	// search for the unused connection with the longest TTL
	for _, c := range s.conns {
		if c.isMarked {
			continue
		}

		remainingTTL := time.Until(c.expiresAt)
		if remainingTTL > maxTTL {
			c.mu.Lock()
			refCount := c.refCount
			c.mu.Unlock()

			// only return conn that is unused
			if refCount == 0 {
				maxTTL = remainingTTL
				conn = c
			}
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

func (s *DynamicConnProvider) lifecycleRoutine() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.markAndCleanupAndReplace()
		case <-s.stopChan:
			return
		}
	}
}

func (s *DynamicConnProvider) markAndCleanupAndReplace() {
	s.mu.Lock()
	defer s.mu.Unlock()

	connsIndexToReplace := make([]int, 0)
	connsIndexToDelete := make([]int, 0)
	now := time.Now()

	for i, conn := range s.conns {
		// mark conns that have reached their mark time
		// and collect them to create their replacement
		if now.After(conn.markedAt) && !conn.isMarked {
			conn.isMarked = true
			connsIndexToReplace = append(connsIndexToReplace, i)
		}

		// collect conns to be deleted, exclude the conns that are being used by the handler (refCount > 0)
		if now.After(conn.deleteAt) {
			conn.mu.Lock()
			refCount := conn.refCount
			conn.mu.Unlock()

			if refCount == 0 {
				connsIndexToDelete = append(connsIndexToDelete, i)
				conn.Quit()
			}
		}
	}

	if len(connsIndexToDelete) > 0 {
		s.logger.Trace("connections to delete", logger.Int("total", len(connsIndexToDelete)))
	}

	// delete inactive connection
	for _, index := range connsIndexToDelete {
		s.conns[index].Quit()
		s.conns[index] = s.conns[len(s.conns)-1]
		s.conns = s.conns[:len(s.conns)-1]
		s.logger.Trace("obsolete connection deleted")
	}

	if len(connsIndexToReplace) > 0 {
		s.logger.Trace("connections to replace", logger.Int("total", len(connsIndexToReplace)))
	}

	// create replacement conns
	for range connsIndexToReplace {
		conn, err := s.createConn(context.Background())
		if err != nil {
			s.logger.Error("error when creating connection", logger.Err(err))
			return
		}
		s.logger.Trace("new replacement connection created")
		s.conns = append(s.conns, conn)
	}
}

func (s *DynamicConnProvider) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, conn := range s.conns {
		conn.Quit()
	}
	close(s.stopChan)
}

func (s *DynamicConnProvider) fetchCredential(ctx context.Context) (*cred.DatabaseUserpass, bool, error) {
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
			LeaseTTL: credential.Data["lease_ttl"],
		}, true, nil
	default:
		return nil, false, fmt.Errorf("unsupported database credential type : %s", credential.Type)
	}
}
