package cert

import (
	"crypto/x509"

	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/logical"
)

// extractClientCert extracts the client certificate from the request.
// Warden always sits behind a load balancer — client certs arrive exclusively
// via the X-SSL-Client-Cert header, parsed by the cert forwarding middleware
// and stored in the request context. On cluster-forwarded requests (standby →
// leader), the header is re-forwarded and re-parsed, so ForwardedClientCert
// works correctly for both direct and forwarded paths.
func extractClientCert(req *logical.Request) *x509.Certificate {
	if req.HTTPRequest == nil {
		return nil
	}

	return listener.ForwardedClientCert(req.HTTPRequest.Context())
}
