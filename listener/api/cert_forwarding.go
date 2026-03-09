package api

import (
	"fmt"
	"net"
	"net/http"

	"github.com/stephnangue/warden/listener"
)

// certForwardingMiddleware returns middleware that extracts client certificates
// from the request. It must run BEFORE middleware.RealIP which overwrites
// r.RemoteAddr.
//
// Certificate extraction follows a two-tier priority:
//
//  1. Forwarding headers from trusted proxies (X-Forwarded-Client-Cert or
//     X-SSL-Client-Cert). Headers from untrusted sources are stripped.
//  2. TLS peer certificates from the direct connection (r.TLS.PeerCertificates).
//     Used as a fallback when no forwarded cert is found — covers direct mTLS
//     connections and load balancers operating in TLS passthrough mode.
//
// The TLS fallback is safe because r.TLS.PeerCertificates is populated by
// Go's TLS stack from the actual handshake and cannot be spoofed via headers.
// This fallback is NOT applied on the cluster listener (which has its own
// handler), so standby-to-leader forwarding never picks up the wrong cert.
func certForwardingMiddleware(trustedProxies []string) func(http.Handler) http.Handler {
	// Pre-parse CIDR networks at startup
	networks := parseCIDRs(trustedProxies)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// --- Header-based extraction ---
			if len(networks) > 0 {
				remoteIP := extractRemoteIP(r.RemoteAddr)
				if remoteIP != nil && isTrustedProxy(remoteIP, networks) {
					// Trusted proxy — extract cert from forwarding headers
					cert := listener.ParseForwardedCert(r)
					if cert != nil {
						ctx := listener.WithForwardedClientCert(r.Context(), cert)
						r = r.WithContext(ctx)
					}
				} else {
					listener.StripCertHeaders(r)
				}
			} else {
				listener.StripCertHeaders(r)
			}

			// --- TLS fallback: direct mTLS or LB passthrough ---
			// When no cert was extracted from headers, check the TLS
			// connection state. This covers two scenarios:
			//   - Direct mTLS connections (no load balancer)
			//   - Load balancers in TLS passthrough mode (no header injection)
			if listener.ForwardedClientCert(r.Context()) == nil &&
				r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				ctx := listener.WithForwardedClientCert(r.Context(), r.TLS.PeerCertificates[0])
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
		})
	}
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
				if ip.To4() != nil {
					_, network, _ = net.ParseCIDR(cidr + "/32")
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
