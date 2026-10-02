package playground

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// TLS is the playground's serving identity: one self-signed certificate for
// localhost that is also the CA every client of the fixtures trusts. It is made
// fresh each run and lives in memory only.
//
// Serving HTTPS rather than plain HTTP is what keeps the configuration the
// playground writes free of tls_skip_verify: a provider or source pointed at an
// http:// URL needs that flag, and it is the one setting nobody should copy.
type TLS struct {
	Certificate tls.Certificate
	// CAPEM is the certificate in PEM form, for settings that take a PEM.
	CAPEM string
	// Pool trusts the certificate, for in-process clients.
	Pool *x509.CertPool
}

// certificateValidity outlives any dev session while still expiring.
const certificateValidity = 30 * 24 * time.Hour

// NewTLS makes the playground's certificate: ECDSA P-256, valid for localhost
// and the loopback addresses. The fixtures are addressed as localhost, not an IP
// literal, because the SSRF guard on credential sources refuses loopback IP
// literals but does not resolve hostnames.
func NewTLS() (*TLS, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate playground TLS key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate playground TLS serial: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Warden playground", Organization: []string{"Warden playground"}},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(certificateValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create playground TLS certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse playground TLS certificate: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &TLS{
		Certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf},
		CAPEM:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		Pool:        pool,
	}, nil
}

// ServerConfig is the TLS configuration the fixtures listen with.
func (t *TLS) ServerConfig() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{t.Certificate}, MinVersion: tls.VersionTLS12}
}

// ClientConfig trusts the fixtures and nothing else.
func (t *TLS) ClientConfig() *tls.Config {
	return &tls.Config{RootCAs: t.Pool, MinVersion: tls.VersionTLS12}
}

// CAData is the certificate as base64-encoded PEM, the form the ca_data setting
// of providers and credential sources takes.
func (t *TLS) CAData() string {
	return base64.StdEncoding.EncodeToString([]byte(t.CAPEM))
}
