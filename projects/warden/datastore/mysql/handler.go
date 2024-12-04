package datastore

import (
	"vitess.io/vitess/go/sqltypes"
	"vitess.io/vitess/go/vt/vtenv"
)

// A Handler is an interface used by Listener to send queries.
// The implementation of this interface may store data in the ClientData
// field of the Connection for its own purposes.
//
// For a given Connection, all these methods are serialized. It means
// only one of these methods will be called concurrently for a given
// Connection. So access to the Connection ClientData does not need to
// be protected by a mutex.
//
// However, each connection is using one go routine, so multiple
// Connection objects can call these concurrently, for different Connections.
type Handler interface {
	// NewConnection is called when a connection is created.
	// It is not established yet. The handler can decide to
	// set StatusFlags that will be returned by the handshake methods.
	// In particular, ServerStatusAutocommit might be set.
	NewConnection(c *Conn)

	// ConnectionReady is called after the connection handshake, but
	// before we begin to process commands.
	ConnectionReady(c *Conn)

	// ConnectionClosed is called when a connection is closed.
	ConnectionClosed(c *Conn)

	// ComQuery is called when a connection receives a query.
	// Note the contents of the query slice may change after
	// the first call to callback. So the Handler should not
	// hang on to the byte slice.
	ComQuery(c *Conn, query string, callback func(*sqltypes.Result) error) error

	// WarningCount is called at the end of each query to obtain
	// the value to be returned to the client in the EOF packet.
	// Note that this will be called either in the context of the
	// ComQuery callback if the result does not contain any fields,
	// or after the last ComQuery call completes.
	WarningCount(c *Conn) uint16

	Env() *vtenv.Environment

	NewSession(c *Session)
	SessionReady(c *Session)
	SessionClosed(c *Session)
	NewComQuery(c *Session, query string, callback func(*sqltypes.Result) error) error
}

// UnimplementedHandler implemnts all of the optional callbacks so as to satisy
// the Handler interface. Intended to be embedded into your custom Handler
// implementation without needing to define every callback and to help be forwards
// compatible when new functions are added.
type UnimplementedHandler struct{}

func (UnimplementedHandler) NewConnection(*Conn)    {}
func (UnimplementedHandler) ConnectionReady(*Conn)  {}
func (UnimplementedHandler) ConnectionClosed(*Conn) {}

func (UnimplementedHandler) NewSession(*Session)    {}
func (UnimplementedHandler) SessionReady(*Session)  {}
func (UnimplementedHandler) SessionClosed(*Session) {}
func (UnimplementedHandler) NewComQuery(*Session, string, func(*sqltypes.Result) error) error {
	return nil
}
