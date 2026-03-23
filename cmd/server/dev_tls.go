package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// generateDevTLSCert creates a self-signed ECDSA P-256 certificate suitable for
// dev mode. The cert and key are written to a temporary directory as PEM files.
// The caller is responsible for cleaning up the returned certDir on shutdown.
func generateDevTLSCert() (certPath, keyPath, certDir string, err error) {
	certDir, err = os.MkdirTemp("", "warden-dev-tls-*")
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create temp dir for dev TLS certs: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		os.RemoveAll(certDir)
		return "", "", "", fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		os.RemoveAll(certDir)
		return "", "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Warden Dev CA",
			Organization: []string{"Warden Dev"},
		},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},

		NotBefore: time.Now().Add(-1 * time.Minute),
		NotAfter:  time.Now().Add(24 * time.Hour),

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		os.RemoveAll(certDir)
		return "", "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		os.RemoveAll(certDir)
		return "", "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certPath = filepath.Join(certDir, "cert.pem")
	keyPath = filepath.Join(certDir, "key.pem")

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		os.RemoveAll(certDir)
		return "", "", "", fmt.Errorf("failed to write cert file: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		os.RemoveAll(certDir)
		return "", "", "", fmt.Errorf("failed to write key file: %w", err)
	}

	return certPath, keyPath, certDir, nil
}
