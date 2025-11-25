package audit

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// SocketSink writes audit logs to a socket (TCP or Unix)
type SocketSink struct {
	mu             sync.Mutex
	network        string
	address        string
	conn           net.Conn
	reconnectDelay time.Duration
	writeTimeout   time.Duration
}

// SocketSinkConfig contains configuration for socket sink
type SocketSinkConfig struct {
	Network        string        // "tcp", "tcp4", "tcp6", "unix", or "unixpacket"
	Address        string        // Address to connect to
	ReconnectDelay time.Duration // Delay between reconnection attempts
	WriteTimeout   time.Duration // Timeout for write operations
}

// NewSocketSink creates a new socket sink
func NewSocketSink(config SocketSinkConfig) (*SocketSink, error) {
	if config.Network == "" {
		config.Network = "tcp"
	}
	
	if config.Address == "" {
		return nil, fmt.Errorf("address is required")
	}
	
	if config.ReconnectDelay == 0 {
		config.ReconnectDelay = 5 * time.Second
	}
	
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 10 * time.Second
	}
	
	sink := &SocketSink{
		network:        config.Network,
		address:        config.Address,
		reconnectDelay: config.ReconnectDelay,
		writeTimeout:   config.WriteTimeout,
	}
	
	// Initial connection
	if err := sink.connect(); err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	
	return sink, nil
}

// connect establishes a connection to the socket
func (s *SocketSink) connect() error {
	conn, err := net.DialTimeout(s.network, s.address, s.writeTimeout)
	if err != nil {
		return err
	}
	
	s.conn = conn
	return nil
}

// reconnect attempts to reconnect to the socket
func (s *SocketSink) reconnect() error {
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	
	return s.connect()
}

// Write writes an entry to the socket
func (s *SocketSink) Write(ctx context.Context, entry []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Ensure we have a connection
	if s.conn == nil {
		if err := s.connect(); err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
	}
	
	// Set write deadline
	if err := s.conn.SetWriteDeadline(time.Now().Add(s.writeTimeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}
	
	// Write entry with newline
	_, err := s.conn.Write(append(entry, '\n'))
	if err != nil {
		// Try to reconnect on error
		if reconnectErr := s.reconnect(); reconnectErr != nil {
			return fmt.Errorf("write failed and reconnect failed: %v, %v", err, reconnectErr)
		}
		
		// Retry write after reconnect
		if err := s.conn.SetWriteDeadline(time.Now().Add(s.writeTimeout)); err != nil {
			return fmt.Errorf("failed to set write deadline after reconnect: %w", err)
		}
		
		_, err = s.conn.Write(append(entry, '\n'))
		if err != nil {
			return fmt.Errorf("write failed after reconnect: %w", err)
		}
	}
	
	return nil
}

// Close closes the socket connection
func (s *SocketSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	
	return nil
}

// Name returns the sink name
func (s *SocketSink) Name() string {
	return fmt.Sprintf("%s://%s", s.network, s.address)
}

// Type returns the sink type
func (s *SocketSink) Type() string {
	return "socket"
}