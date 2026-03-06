package api

import (
	"fmt"
	"net"
	"net/http"

	"github.com/stephnangue/warden/listener"
)

// certForwardingMiddleware returns middleware that extracts client certificates
// from forwarding headers sent by trusted proxies. It must run BEFORE
// middleware.RealIP which overwrites r.RemoteAddr.
//
// When the request comes from a trusted proxy IP:
//   - Parses X-Forwarded-Client-Cert (XFCC, Envoy/Istio) or
//     X-SSL-Client-Cert (NGINX/HAProxy) headers
//   - Stores the parsed certificate in the request context
//   - Strips the forwarding headers to prevent downstream leakage
//
// When the request comes from an untrusted IP:
//   - Deletes any forwarding headers to prevent spoofing
func certForwardingMiddleware(trustedProxies []string) func(http.Handler) http.Handler {
	// Pre-parse CIDR networks at startup
	networks := parseCIDRs(trustedProxies)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If no trusted proxies configured, strip headers and pass through
			if len(networks) == 0 {
				listener.StripCertHeaders(r)
				next.ServeHTTP(w, r)
				return
			}

			remoteIP := extractRemoteIP(r.RemoteAddr)
			if remoteIP == nil {
				listener.StripCertHeaders(r)
				next.ServeHTTP(w, r)
				return
			}

			if !isTrustedProxy(remoteIP, networks) {
				listener.StripCertHeaders(r)
				next.ServeHTTP(w, r)
				return
			}

			// Trusted proxy — extract cert from forwarding headers
			cert := listener.ParseForwardedCert(r)

			if cert != nil {
				ctx := listener.WithForwardedClientCert(r.Context(), cert)
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
