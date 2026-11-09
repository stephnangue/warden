package listener

import (
	"net"
	"net/http"
)

// ClientIP is the address of the client that made r. The listener that
// accepted r has already resolved it into r.RemoteAddr — from the connection,
// or from a trusted proxy's or forwarding node's headers — so it is read from
// there and nowhere else: a forwarding header a caller sends is not evidence
// of anything.
func ClientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
