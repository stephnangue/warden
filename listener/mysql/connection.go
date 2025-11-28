package mysql

import (
	"context"
	"sync"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
)

type ConnProvider interface {
	GetConn(ctx context.Context) (*BackendConn, error)
	Stop()
}

type BackendConn struct {
	*client.Conn

	// refCount tracks the number of reference of this conn being used by the handler
	// only one reference should be use at a time
	refCount int32
	mu       sync.Mutex

	// all the fields below are used only by dynamic conn provider

	createdAt time.Time

	// this is used to track the must fresh conn,
	// that is the conn that will expire the latest
	expiresAt time.Time

	// a conn that reached the expiration time is marked
	// once marked, it cannot the fetched to handle queries
	// this is used as a draining mechanism before closing the conn
	markedAt time.Time
	isMarked bool

	// when to close and delete the conn
	deleteAt time.Time
}

// Release is called when the handler no longer needs a conn
func (c *BackendConn) Release() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refCount > 0 {
		c.refCount--
	}
}
