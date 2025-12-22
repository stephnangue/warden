package mysql

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stephnangue/warden/authorize"
	"github.com/stephnangue/warden/cred"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/target"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Helper function to create a test logger
func newTestLogger() *logger.GatedLogger {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	return log
}

// MockListener is a mock implementation of net.Listener
type MockListener struct {
	mock.Mock
	addr net.Addr
}

func (m *MockListener) Accept() (net.Conn, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(net.Conn), args.Error(1)
}

func (m *MockListener) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockListener) Addr() net.Addr {
	return m.addr
}

// MockConn is a mock implementation of net.Conn
type MockConn struct {
	mock.Mock
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	args := m.Called(b)
	return args.Int(0), args.Error(1)
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	args := m.Called(b)
	return args.Int(0), args.Error(1)
}

func (m *MockConn) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockConn) LocalAddr() net.Addr {
	args := m.Called()
	return args.Get(0).(net.Addr)
}

func (m *MockConn) RemoteAddr() net.Addr {
	args := m.Called()
	return args.Get(0).(net.Addr)
}

func (m *MockConn) SetDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

func (m *MockConn) SetReadDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

func (m *MockConn) SetWriteDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

func TestNewMysqlListener_WithProvidedListener(t *testing.T) {
	mockListener := &MockListener{
		addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3306},
	}
	testLogger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	roles := &authorize.RoleRegistry{}
	credSources := &cred.CredSourceRegistry{}
	targets := &target.TargetRegistry{}

	cfg := MysqlListenerConfig{
		Listener:    mockListener,
		Logger:      testLogger,
		Roles:       roles,
		CredSources: credSources,
		Targets:     targets,
	}

	listener, err := NewMysqlListener(cfg)

	require.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, mockListener, listener.listener)
	assert.Equal(t, testLogger, listener.logger)
	assert.Equal(t, roles, listener.roles)
	assert.Equal(t, credSources, listener.credSources)
	assert.Equal(t, targets, listener.targets)
	assert.NotNil(t, listener.server)
}

func TestNewMysqlListener_WithProtocolAndAddress(t *testing.T) {
	testLogger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	roles := &authorize.RoleRegistry{}
	credSources := &cred.CredSourceRegistry{}
	targets := &target.TargetRegistry{}

	cfg := MysqlListenerConfig{
		Protocol:    "tcp",
		Address:     "127.0.0.1:0", // Use port 0 to get a random available port
		Logger:      testLogger,
		Roles:       roles,
		CredSources: credSources,
		Targets:     targets,
	}

	listener, err := NewMysqlListener(cfg)

	require.NoError(t, err)
	assert.NotNil(t, listener)
	assert.NotNil(t, listener.listener)

	// Clean up
	listener.Stop()
}

func TestNewMysqlListener_WithProxyProtocol(t *testing.T) {
	testLogger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	roles := &authorize.RoleRegistry{}
	credSources := &cred.CredSourceRegistry{}
	targets := &target.TargetRegistry{}

	cfg := MysqlListenerConfig{
		Protocol:      "tcp",
		Address:       "127.0.0.1:0",
		ProxyProtocol: true,
		Logger:        testLogger,
		Roles:         roles,
		CredSources:   credSources,
		Targets:       targets,
	}

	listener, err := NewMysqlListener(cfg)

	require.NoError(t, err)
	assert.NotNil(t, listener)
	assert.NotNil(t, listener.listener)

	// Clean up
	listener.Stop()
}

func TestNewMysqlListener_InvalidAddress(t *testing.T) {
	testLogger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	roles := &authorize.RoleRegistry{}
	credSources := &cred.CredSourceRegistry{}
	targets := &target.TargetRegistry{}

	cfg := MysqlListenerConfig{
		Protocol:    "tcp",
		Address:     "invalid:address:format",
		Logger:      testLogger,
		Roles:       roles,
		CredSources: credSources,
		Targets:     targets,
	}

	listener, err := NewMysqlListener(cfg)

	assert.Error(t, err)
	assert.Nil(t, listener)
}

func TestMysqlListener_Addr(t *testing.T) {
	expectedAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3306}
	mockListener := &MockListener{addr: expectedAddr}
	testLogger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	listener := &MysqlListener{
		listener: mockListener,
		logger:   testLogger,
	}

	addr := listener.Addr()

	assert.Equal(t, expectedAddr.String(), addr)
}

func TestMysqlListener_Stop(t *testing.T) {
	mockListener := new(MockListener)
	mockListener.On("Close").Return(nil)
	testLogger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	listener := &MysqlListener{
		listener: mockListener,
		logger:   testLogger,
	}

	listener.Stop()

	mockListener.AssertExpectations(t)
}

func TestMysqlListener_Start_AcceptError(t *testing.T) {
	mockListener := new(MockListener)
	testLogger, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	expectedErr := errors.New("accept error")
	mockListener.On("Accept").Return(nil, expectedErr).Once()

	listener := &MysqlListener{
		listener: mockListener,
		logger:   testLogger,
	}

	// Start will block, so run it in a goroutine
	done := make(chan bool)
	go func() {
		listener.Start(context.Background())
		done <- true
	}()

	// Wait for Start to return
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Start() did not return in time")
	}

	mockListener.AssertExpectations(t)
}
