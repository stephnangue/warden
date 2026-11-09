package dualgateway

import "testing"

func TestShutdownHTTPTransport(t *testing.T) {
	// Should not panic even when called before initTransport
	ShutdownHTTPTransport()
}

// The transport sets no header timeout of its own: the mount's timeout is the
// deadline of every forwarded request, and a fixed one here would cut a slow
// call short of it.
func TestTransport_NoResponseHeaderTimeout(t *testing.T) {
	if got := newTransport().ResponseHeaderTimeout; got != 0 {
		t.Fatalf("newTransport ResponseHeaderTimeout = %v, want 0", got)
	}
	tlsTransport, err := newTransportWithTLS("", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := tlsTransport.ResponseHeaderTimeout; got != 0 {
		t.Fatalf("newTransportWithTLS ResponseHeaderTimeout = %v, want 0", got)
	}
}

func TestInitTransport(t *testing.T) {
	initTransport()
	if sharedTransport == nil {
		t.Fatal("sharedTransport should be initialized after initTransport()")
	}
}
