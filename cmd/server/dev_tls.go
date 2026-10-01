package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// generateDevTLSCert creates a self-signed ECDSA P-256 certificate suitable for
// dev mode and writes it as cert.pem and key.pem.
//
// When dir is empty the files go to a fresh temporary directory, which the
// caller removes on shutdown. When dir is set it is created if missing and the
// files are written there and left in place after shutdown, so a host can trust
// a certificate generated inside a container through a mounted directory.
//
// The certificate always covers localhost and the loopback addresses; each
// entry in sans is added as an IP SAN when it parses as an IP, otherwise as a
// DNS SAN.
func generateDevTLSCert(dir string, sans []string) (certPath, keyPath, certDir string, err error) {
	temp := dir == ""
	if temp {
		certDir, err = os.MkdirTemp("", "warden-dev-tls-*")
		if err != nil {
			return "", "", "", fmt.Errorf("failed to create temp dir for dev TLS certs: %w", err)
		}
	} else {
		certDir = dir
		if err := os.MkdirAll(certDir, 0o700); err != nil {
			return "", "", "", fmt.Errorf("failed to create dev TLS cert dir %q: %w", certDir, err)
		}
	}

	certPath = filepath.Join(certDir, "cert.pem")
	keyPath = filepath.Join(certDir, "key.pem")

	// A user-supplied directory may be a mounted volume holding other files,
	// including a previous run's certificate, so only the files this call
	// wrote are removed on failure.
	var written []string
	cleanup := func() {
		if temp {
			os.RemoveAll(certDir)
			return
		}
		for _, path := range written {
			os.Remove(path)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		cleanup()
		return "", "", "", fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		cleanup()
		return "", "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Warden Dev CA",
			Organization: []string{"Warden Dev"},
		},
		DNSNames:    []string{"localhost", "*.localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},

		NotBefore: time.Now().Add(-1 * time.Minute),
		NotAfter:  time.Now().Add(24 * time.Hour),

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	addDevTLSSANs(template, sans)

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		cleanup()
		return "", "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		cleanup()
		return "", "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := writeFileMode(certPath, certPEM, 0o644); err != nil {
		cleanup()
		return "", "", "", fmt.Errorf("failed to write cert file: %w", err)
	}
	written = append(written, certPath)
	if err := writeFileMode(keyPath, keyPEM, 0o600); err != nil {
		cleanup()
		return "", "", "", fmt.Errorf("failed to write key file: %w", err)
	}

	return certPath, keyPath, certDir, nil
}

// addDevTLSSANs appends each SAN, trimmed of surrounding space, to the
// certificate template as an IP or DNS name, skipping any the template already
// carries.
func addDevTLSSANs(template *x509.Certificate, sans []string) {
	for _, san := range sans {
		san = strings.TrimSpace(san)
		if san == "" {
			continue
		}
		if ip := net.ParseIP(san); ip != nil {
			if !slices.ContainsFunc(template.IPAddresses, ip.Equal) {
				template.IPAddresses = append(template.IPAddresses, ip)
			}
			continue
		}
		if !slices.Contains(template.DNSNames, san) {
			template.DNSNames = append(template.DNSNames, san)
		}
	}
}

// writeFileMode replaces path with a new file holding data, created with perm.
// A file left by a previous run is removed first, since os.WriteFile keeps the
// mode of an existing file and a regenerated private key must not inherit a
// looser one.
func writeFileMode(path string, data []byte, perm os.FileMode) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return writeNewFile(path, data, perm)
}

// writeNewFile creates path exclusively and writes data to it. O_EXCL refuses
// any existing entry, including a symlink planted after the removal in
// writeFileMode, so the data never lands in a file chosen by someone else who
// can write to the directory. A partly written file is removed on error.
func writeNewFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

// validateDevTLSGenFlags checks the flags that shape the auto-generated dev
// certificate: they need -dev, apply only when Warden generates the
// certificate, and every SAN must be non-empty.
func validateDevTLSGenFlags(dev bool, certDir string, sans []string, certFile, keyFile string) error {
	if certDir == "" && len(sans) == 0 {
		return nil
	}
	if !dev {
		return fmt.Errorf("-dev-tls-cert-dir and -dev-tls-san can only be used with -dev")
	}
	if certFile != "" || keyFile != "" {
		return fmt.Errorf("-dev-tls-cert-dir and -dev-tls-san shape the auto-generated certificate and cannot be combined with -dev-tls-cert-file/-dev-tls-key-file")
	}
	for _, san := range sans {
		if strings.TrimSpace(san) == "" {
			return fmt.Errorf("-dev-tls-san must not be empty")
		}
	}
	return nil
}
