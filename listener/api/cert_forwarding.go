package api

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/middleware"
	"github.com/stephnangue/warden/listener"
)

// trustedForwardingMiddleware decides, from the connection's own peer address,
// what the request says about itself: the client certificate, the client IP
// and the request id. A load balancer in trusted_proxies may speak for the
// client through forwarding headers; anyone else may not, so their forwarding
// headers are ignored and a caller cannot choose the identity it is logged in
// as or the IP its token is bound to or matched against.
//
// It must run before anything rewrites r.RemoteAddr, and it is the only thing
// that does: afterwards r.RemoteAddr holds the client's address, which is all
// the rest of Warden reads.
//
//   - Client IP: from a trusted proxy, the rightmost X-Forwarded-For entry
//     that is not itself a trusted proxy (entries further left are whatever
//     the client sent) — or the peer, if an entry cannot be read — and
//     X-Real-IP only when there is no X-Forwarded-For; from anyone else, the
//     peer.
//   - Request id: a trusted proxy's X-Request-Id, when it is a plausible id,
//     else a new one. It is only as good as the proxy: one that passes the
//     client's header through, rather than setting its own, lets the client
//     pick it. The header itself is left as sent, so it still reaches the
//     upstream; the cluster's internal id header is removed, since only a
//     forwarding node may set it.
//   - Client certificate: from a trusted proxy, its forwarding headers
//     (X-Forwarded-Client-Cert or X-SSL-Client-Cert); from anyone else those
//     headers are stripped. Failing that, the certificate of the TLS
//     connection itself — a direct mTLS client, or a load balancer in TLS
//     passthrough — which Go's TLS stack took from the handshake, so it cannot
//     be forged through a header. The cluster listener does not use this
//     middleware, so standby-to-leader forwarding never picks up a node's
//     certificate as the client's.
func trustedForwardingMiddleware(trustedProxies []string) func(http.Handler) http.Handler {
	networks := parseCIDRs(trustedProxies)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			trusted := false
			if len(networks) > 0 {
				if peer := extractRemoteIP(r.RemoteAddr); peer != nil {
					trusted = isTrustedProxy(peer, networks)
				}
			}

			requestID := ""
			if trusted {
				if ip := forwardedClientIP(r, networks); ip != nil {
					r.RemoteAddr = withHost(r.RemoteAddr, ip)
				}
				if cert := listener.ParseForwardedCert(r); cert != nil {
					ctx = listener.WithForwardedClientCert(ctx, cert)
				}
				requestID = r.Header.Get(middleware.RequestIDHeader)
			} else {
				listener.StripCertHeaders(r)
			}
			r.Header.Del(listener.ForwardedRequestIDHeader)
			if !plausibleRequestID(requestID) {
				requestID = listener.NewRequestID()
			}
			ctx = listener.WithRequestID(ctx, requestID)

			if listener.ForwardedClientCert(ctx) == nil &&
				r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				ctx = listener.WithForwardedClientCert(ctx, r.TLS.PeerCertificates[0])
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// forwardedClientIP is the client's address as a trusted proxy reports it:
// walking X-Forwarded-For from the right, the first entry that is not a
// trusted proxy — the entries to its left were sent by the client — or, when
// every entry is trusted, the leftmost. Without X-Forwarded-For, X-Real-IP.
// Nil when neither holds a valid address.
func forwardedClientIP(r *http.Request, networks []*net.IPNet) net.IP {
	if values := r.Header.Values("X-Forwarded-For"); len(values) > 0 {
		entries := strings.Split(strings.Join(values, ","), ",")
		var leftmost net.IP
		for i := len(entries) - 1; i >= 0; i-- {
			ip := parseForwardedAddr(entries[i])
			if ip == nil {
				// An entry that cannot be read cannot be vetted, and every
				// entry to its left came through it: stop, rather than walk
				// on to one the client wrote.
				return nil
			}
			if !isTrustedProxy(ip, networks) {
				return ip
			}
			leftmost = ip
		}
		if leftmost != nil {
			return leftmost
		}
	}
	return net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP")))
}

// plausibleRequestID reports whether a proxy-supplied id is fit to be audited
// as one: non-empty, at most 128 characters, and made of the characters ids
// are made of, so a header cannot smuggle arbitrary text into the audit log.
func plausibleRequestID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.IndexByte("-_.:/+=", c) >= 0) {
			return false
		}
	}
	return true
}

// parseForwardedAddr reads one X-Forwarded-For entry: a bare address, or one
// with a port as some proxies write it ("203.0.113.7:4567", "[2001:db8::7]:443").
func parseForwardedAddr(entry string) net.IP {
	entry = strings.TrimSpace(entry)
	if ip := net.ParseIP(entry); ip != nil {
		return ip
	}
	if host, _, err := net.SplitHostPort(entry); err == nil {
		return net.ParseIP(host)
	}
	return nil
}

// withHost replaces the host of a host:port address, keeping the port, so
// r.RemoteAddr keeps the shape net/http gives it.
func withHost(remoteAddr string, ip net.IP) string {
	if _, port, err := net.SplitHostPort(remoteAddr); err == nil {
		return net.JoinHostPort(ip.String(), port)
	}
	return ip.String()
}

func extractRemoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// Try parsing as bare IP
		return net.ParseIP(remoteAddr)
	}
	return net.ParseIP(host)
}

func isTrustedProxy(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateCIDRs checks that all entries are valid CIDR notations or bare IPs.
// Returns an error listing any unparseable entries, so misconfigurations are
// caught at startup rather than silently ignored.
func ValidateCIDRs(cidrs []string) error {
	var invalid []string
	for _, cidr := range cidrs {
		_, _, err := net.ParseCIDR(cidr)
		if err != nil {
			// Allow bare IPs (they get /32 or /128 in parseCIDRs)
			if net.ParseIP(cidr) == nil {
				invalid = append(invalid, cidr)
			}
		}
	}
	if len(invalid) > 0 {
		return fmt.Errorf("invalid trusted_proxies entries: %v", invalid)
	}
	return nil
}

func parseCIDRs(cidrs []string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try as single IP (add /32 or /128)
			ip := net.ParseIP(cidr)
			if ip != nil {
				if v4 := ip.To4(); v4 != nil {
					// From v4's own text: an IPv4-mapped form such as
					// "::ffff:10.0.0.5" would otherwise parse as ::/32.
					_, network, _ = net.ParseCIDR(v4.String() + "/32")
				} else {
					_, network, _ = net.ParseCIDR(cidr + "/128")
				}
				if network != nil {
					networks = append(networks, network)
				}
			}
			continue
		}
		networks = append(networks, network)
	}
	return networks
}
