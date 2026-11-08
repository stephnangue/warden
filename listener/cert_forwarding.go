package listener

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type contextKey string

const ctxForwardedClientCert contextKey = "forwarded_client_cert"

// ForwardedCertHandshakeHeader tells the active node that the client
// certificate a standby forwards came from that standby's own TLS handshake
// with the client. It is internal to the cluster: the forwarding proxy sets it
// and the cluster listener consumes it. Its only accepted value is
// ForwardedCertHandshakeTrue; anything else, or nothing, is a certificate a
// header supplied.
const (
	ForwardedCertHandshakeHeader = "X-Warden-Forwarded-Cert-Handshake"
	ForwardedCertHandshakeTrue   = "true"
)

// clientCert is a request's client certificate and how Warden came by it.
// handshake is true only when the certificate came from a TLS handshake with
// the client, on this node or on the standby that forwarded the request: the
// client then proved it holds the certificate's key. It says nothing of
// whether the certificate is trusted, which is for the auth mount to decide.
type clientCert struct {
	cert      *x509.Certificate
	handshake bool
}

// ForwardedClientCert retrieves the client certificate stored in the context
// by the cert forwarding middleware. The cert may originate from a forwarding
// header (trusted proxy / LB), the TLS connection state (direct mTLS / LB
// passthrough), or re-injection by the cluster listener on forwarded requests.
func ForwardedClientCert(ctx context.Context) *x509.Certificate {
	cc, _ := ctx.Value(ctxForwardedClientCert).(clientCert)
	return cc.cert
}

// ClientCertFromHandshake reports whether the context's client certificate came
// from a TLS handshake with the client (see clientCert). False when there is
// no certificate.
func ClientCertFromHandshake(ctx context.Context) bool {
	cc, _ := ctx.Value(ctxForwardedClientCert).(clientCert)
	return cc.handshake
}

// WithForwardedClientCert returns a new context holding a client certificate
// that a header supplied, which proves nothing about who holds its key.
func WithForwardedClientCert(ctx context.Context, cert *x509.Certificate) context.Context {
	return context.WithValue(ctx, ctxForwardedClientCert, clientCert{cert: cert})
}

// WithHandshakeClientCert returns a new context holding a client certificate
// that came from a TLS handshake with the client.
func WithHandshakeClientCert(ctx context.Context, cert *x509.Certificate) context.Context {
	return context.WithValue(ctx, ctxForwardedClientCert, clientCert{cert: cert, handshake: true})
}

// ParseForwardedCert extracts a client certificate from forwarding headers
// (X-Forwarded-Client-Cert or X-SSL-Client-Cert) and strips the headers.
func ParseForwardedCert(r *http.Request) *x509.Certificate {
	cert := ParseCertFromHeaders(r)
	StripCertHeaders(r)
	return cert
}

// ParseCertFromHeaders tries to extract a client certificate from forwarding headers.
// Checks X-Forwarded-Client-Cert (XFCC) first, then X-SSL-Client-Cert.
func ParseCertFromHeaders(r *http.Request) *x509.Certificate {
	if xfcc := r.Header.Get("X-Forwarded-Client-Cert"); xfcc != "" {
		if cert := ParseXFCCHeader(xfcc); cert != nil {
			return cert
		}
	}

	if sslCert := r.Header.Get("X-SSL-Client-Cert"); sslCert != "" {
		if cert := ParseSSLClientCertHeader(sslCert); cert != nil {
			return cert
		}
	}

	return nil
}

// ParseXFCCHeader parses the X-Forwarded-Client-Cert header (Envoy/Istio format).
// Format: Hash=<hex-encoded SHA-256>;Cert="<URL-encoded PEM>";Subject="..."
//
// When a Hash field is present, it is validated against the SHA-256 fingerprint
// of the extracted certificate. A mismatch returns nil (cert rejected).
func ParseXFCCHeader(xfcc string) *x509.Certificate {
	var certValue, hashValue string

	for _, part := range strings.Split(xfcc, ";") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "Cert="):
			certValue = strings.TrimPrefix(part, "Cert=")
			certValue = strings.Trim(certValue, "\"")
		case strings.HasPrefix(part, "Hash="):
			hashValue = strings.TrimPrefix(part, "Hash=")
			hashValue = strings.Trim(hashValue, "\"")
		}
	}

	if certValue == "" {
		return nil
	}

	decoded, err := url.QueryUnescape(certValue)
	if err != nil {
		return nil
	}
	cert := ParsePEMCertificate(decoded)
	if cert == nil {
		return nil
	}

	if hashValue != "" {
		fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
		normalizedHash := strings.ToLower(strings.ReplaceAll(hashValue, ":", ""))
		if normalizedHash != fingerprint {
			if decoded, err := hex.DecodeString(normalizedHash); err == nil {
				expected := sha256.Sum256(cert.Raw)
				if subtle.ConstantTimeCompare(decoded, expected[:]) != 1 {
					return nil
				}
			} else {
				return nil
			}
		}
	}

	return cert
}

// ParseSSLClientCertHeader parses the X-SSL-Client-Cert header (NGINX/HAProxy format).
// The value is a URL-encoded PEM certificate.
func ParseSSLClientCertHeader(value string) *x509.Certificate {
	decoded, err := url.QueryUnescape(value)
	if err != nil {
		return nil
	}
	return ParsePEMCertificate(decoded)
}

// ParsePEMCertificate parses a PEM-encoded certificate string.
func ParsePEMCertificate(pemData string) *x509.Certificate {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return cert
}

// StripCertHeaders removes cert forwarding headers from the request.
func StripCertHeaders(r *http.Request) {
	r.Header.Del("X-Forwarded-Client-Cert")
	r.Header.Del("X-SSL-Client-Cert")
}
