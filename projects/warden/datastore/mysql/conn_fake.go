package datastore

import (
	"fmt"
	"net"
	"time"
)

// testConn to be used for testing only as net.Conn interface implementation.
type testConn struct {
	writeToPass []bool
	pos         int
	queryPacket []byte
}

func (t testConn) Read(b []byte) (n int, err error) {
	copy(b, t.queryPacket)
	return len(b), nil
}

func (t testConn) Write(b []byte) (n int, err error) {
	t.pos = t.pos + 1
	if t.writeToPass[t.pos] {
		return 0, nil
	}
	return 0, fmt.Errorf("error in writing to connection")
}

func (t testConn) Close() error {
	return nil
}

func (t testConn) LocalAddr() net.Addr {
	panic("implement me")
}

func (t testConn) RemoteAddr() net.Addr {
	return mockAddress{s: "a"}
}

func (t testConn) SetDeadline(t1 time.Time) error {
	panic("implement me")
}

func (t testConn) SetReadDeadline(t1 time.Time) error {
	panic("implement me")
}

func (t testConn) SetWriteDeadline(t1 time.Time) error {
	panic("implement me")
}

var _ net.Conn = (*testConn)(nil)

type mockAddress struct {
	s string
}

func (m mockAddress) Network() string {
	return m.s
}

func (m mockAddress) String() string {
	return m.s
}

var _ net.Addr = (*mockAddress)(nil)

// GetTestConn returns a conn for testing purpose only.
func GetTestConn() *Conn {
	return newConn(testConn{}, DefaultFlushDelay, 0)
}

// GetTestServerConn is only meant to be used for testing.
// It creates a server connection using a testConn and the provided listener.
func GetTestServerConn(listener *Listener) *Conn {
	return newServerConn(testConn{}, listener)
}
