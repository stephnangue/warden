package cert

import (
	"crypto/x509"

	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/logical"
)

// extractClientCert extracts the client certificate from the request.
// The cert forwarding middleware stores it in the request context after
// extracting it from either a forwarding header (X-SSL-Client-Cert or
// X-Forwarded-Client-Cert from a trusted proxy) or the TLS connection
// state (r.TLS.PeerCertificates for direct mTLS / LB passthrough).
// On cluster-forwarded requests (standby → leader), the header is
// re-forwarded and re-parsed, so ForwardedClientCert works correctly
// for all paths.
func extractClientCert(req *logical.Request) *x509.Certificate {
	if req.HTTPRequest == nil {
		return nil
	}

	return listener.ForwardedClientCert(req.HTTPRequest.Context())
}
