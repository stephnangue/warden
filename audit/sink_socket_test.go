package audit

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestSocketSinkNewAndWrite(t *testing.T) {
	// Start a TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Read and discard
			buf := make([]byte, 4096)
			for {
				_, err := conn.Read(buf)
				if err != nil {
					conn.Close()
					return
				}
			}
		}
	}()

	sink, err := NewSocketSink(SocketSinkConfig{
		Address:      ln.Addr().String(),
		WriteTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSocketSink failed: %v", err)
	}

	if err := sink.Write(context.Background(), []byte(`{"test":"data"}`)); err != nil {
		t.Errorf("Write failed: %v", err)
	}

	if sink.Name() == "" {
		t.Error("expected non-empty name")
	}
	if sink.Type() != "socket" {
		t.Errorf("expected socket, got %s", sink.Type())
	}

	if err := sink.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Close again should not error
	if err := sink.Close(); err != nil {
		t.Errorf("second Close failed: %v", err)
	}
}

func TestSocketSinkMissingAddress(t *testing.T) {
	_, err := NewSocketSink(SocketSinkConfig{})
	if err == nil {
		t.Error("expected error for missing address")
	}
}

func TestSocketSinkConnectionFailure(t *testing.T) {
	_, err := NewSocketSink(SocketSinkConfig{
		Address:      "127.0.0.1:1", // unlikely to be listening
		WriteTimeout: 1 * time.Second,
	})
	if err == nil {
		t.Error("expected connection error")
	}
}
