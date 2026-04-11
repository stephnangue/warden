package dualgateway

import "testing"

func TestShutdownHTTPTransport(t *testing.T) {
	// Should not panic even when called before initTransport
	ShutdownHTTPTransport()
}

func TestInitTransport(t *testing.T) {
	initTransport()
	if sharedTransport == nil {
		t.Fatal("sharedTransport should be initialized after initTransport()")
	}
}
