package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/stephnangue/warden/logger"
)

const (
	// corePrivateKeyTypeP521 is the key type identifier stored in
	// ClusterKeyParams for P-521 ECDSA keys.
	corePrivateKeyTypeP521 = "p521"
)

// setupCluster generates a new P-521 ECDSA key pair and self-signed
// certificate for cluster-internal mTLS. Called when a node becomes
// active. The cert/key are stored in Core's atomic pointers (memory
// only) and later included in the leader advertisement for standbys.
//
// Adapted from OpenBao vault/cluster.go:setupCluster.
func (c *Core) setupCluster(ctx context.Context) error {
	// Only generate cluster identity when HA and clustering are enabled.
	if c.ha == nil {
		return nil
	}

	if c.clusterAddrValue() == "" {
		c.logger.Debug("cluster address not set, skipping cluster TLS setup")
		return nil
	}

	// Generate a P-521 ECDSA private key.
	c.logger.Debug("generating cluster private key")
	key, err := ecdsa.GenerateKey(elliptic.P521(), c.secureRandomReader)
	if err != nil {
		c.logger.Error("failed to generate cluster private key", logger.Err(err))
		return err
	}
	// Generate a unique hostname for the certificate CN.
	host, err := uuid.GenerateUUID()
	if err != nil {
		return fmt.Errorf("failed to generate cluster cert hostname: %w", err)
	}
	host = fmt.Sprintf("fw-%s", host)

	c.logger.Debug("generating cluster certificate", logger.String("host", host))

	// Generate a cryptographically secure serial number (RFC 5280 §4.1.2.2).
	serialBytes := make([]byte, 16)
	if _, err := rand.Read(serialBytes); err != nil {
		return fmt.Errorf("failed to generate certificate serial number: %w", err)
	}
	serialBytes[0] &= 0x7F // ensure positive
	serial := new(big.Int).SetBytes(serialBytes)

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: host,
		},
		DNSNames: []string{host},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		SerialNumber:          serial,
		NotBefore:             time.Now().Add(-30 * time.Second),  // clock skew grace
		NotAfter:              time.Now().Add(262980 * time.Hour), // ~30 years
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-signed: template is both the template and the parent.
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		c.logger.Error("failed to generate cluster certificate", logger.Err(err))
		return fmt.Errorf("failed to generate cluster certificate: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		c.logger.Error("failed to parse generated cluster certificate", logger.Err(err))
		return fmt.Errorf("failed to parse generated cluster certificate: %w", err)
	}

	// Sanity check: verify the cert is valid at the current time.
	// Guards against extreme clock drift or NTP jumps.
	now := time.Now()
	if now.Before(parsedCert.NotBefore) || now.After(parsedCert.NotAfter) {
		return fmt.Errorf("generated cluster certificate not valid at current time (notBefore=%s, notAfter=%s, now=%s)",
			parsedCert.NotBefore, parsedCert.NotAfter, now)
	}

	// Store the new identity. All three stores happen in sequence
	// without a prior clear, so ClusterTLSConfig() never observes
	// a nil window during leadership transitions.
	c.localClusterPrivateKey.Store(key)
	c.localClusterCert.Store(&certBytes)
	c.localClusterParsedCert.Store(parsedCert)

	c.logger.Info("cluster TLS identity generated",
		logger.String("cn", host),
		logger.String("serial", parsedCert.SerialNumber.String()))

	return nil
}

// loadLocalClusterTLS reconstructs the cluster TLS identity from a
// leader advertisement. Called by standby nodes when they read the
// active node's advertisement from barrier storage.
//
// Adapted from OpenBao vault/cluster.go:loadLocalClusterTLS.
func (c *Core) loadLocalClusterTLS(adv activeAdvertisement) error {
	switch {
	case adv.ClusterAddr == "":
		// Clustering disabled on the leader; nothing to load.
		return nil

	case adv.ClusterKeyParams == nil:
		c.logger.Error("no cluster key params in leader advertisement")
		return errors.New("no cluster key params found in leader advertisement")

	case adv.ClusterKeyParams.X == nil, adv.ClusterKeyParams.Y == nil, adv.ClusterKeyParams.D == nil:
		c.logger.Error("incomplete cluster key params in leader advertisement")
		return errors.New("incomplete cluster key params in leader advertisement")

	case adv.ClusterKeyParams.Type != corePrivateKeyTypeP521:
		c.logger.Error("unknown cluster key type", logger.String("type", adv.ClusterKeyParams.Type))
		return fmt.Errorf("unknown cluster key type: %s", adv.ClusterKeyParams.Type)

	case len(adv.ClusterCert) == 0:
		c.logger.Error("no cluster cert in leader advertisement")
		return errors.New("no cluster cert in leader advertisement")
	}

	// Reconstruct the ECDSA private key from the advertised parameters.
	c.localClusterPrivateKey.Store(&ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P521(),
			X:     adv.ClusterKeyParams.X,
			Y:     adv.ClusterKeyParams.Y,
		},
		D: adv.ClusterKeyParams.D,
	})

	// Copy the DER cert bytes so we own the memory.
	locCert := make([]byte, len(adv.ClusterCert))
	copy(locCert, adv.ClusterCert)
	c.localClusterCert.Store(&locCert)

	parsedCert, err := x509.ParseCertificate(adv.ClusterCert)
	if err != nil {
		c.logger.Error("failed to parse cluster cert from leader advertisement", logger.Err(err))
		return fmt.Errorf("failed to parse cluster cert: %w", err)
	}
	c.localClusterParsedCert.Store(parsedCert)

	return nil
}

// clearClusterTLS removes the in-memory cluster TLS identity.
// Called during step-down or pre-seal.
func (c *Core) clearClusterTLS() {
	c.localClusterCert.Store(nil)
	c.localClusterParsedCert.Store(nil)
	c.localClusterPrivateKey.Store(nil)
}

// ClusterTLSConfig builds a *tls.Config from the current in-memory
// cluster identity. Returns nil if the cluster identity is not loaded.
// The returned config enforces mutual TLS: the self-signed cert serves
// as both the node's identity and the CA for verifying peers.
func (c *Core) ClusterTLSConfig() *tls.Config {
	certPtr := c.localClusterCert.Load()
	keyPtr := c.localClusterPrivateKey.Load()
	parsedPtr := c.localClusterParsedCert.Load()

	if certPtr == nil || keyPtr == nil || parsedPtr == nil {
		return nil
	}

	certDER := *certPtr
	key := keyPtr
	parsed := parsedPtr

	// Build a CA pool containing only our self-signed cert.
	caPool := x509.NewCertPool()
	caPool.AddCert(parsed)

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{certDER},
				PrivateKey:  key,
				Leaf:        parsed,
			},
		},
		RootCAs:    caPool, // verify server cert (standby → active)
		ClientCAs:  caPool, // verify client cert (active ← standby)
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
}

// clusterKeyParams returns the ClusterKeyParams for the current
// in-memory private key, suitable for inclusion in a leader
// advertisement. Returns nil if no key is loaded.
func (c *Core) clusterKeyParams() *certutil.ClusterKeyParams {
	key := c.localClusterPrivateKey.Load()
	if key == nil {
		return nil
	}
	return &certutil.ClusterKeyParams{
		Type: corePrivateKeyTypeP521,
		X:    key.X,
		Y:    key.Y,
		D:    key.D,
	}
}

// clusterCertDER returns a copy of the DER-encoded cluster cert,
// suitable for inclusion in a leader advertisement.
// Returns nil if no cert is loaded.
func (c *Core) clusterCertDER() []byte {
	certPtr := c.localClusterCert.Load()
	if certPtr == nil {
		return nil
	}
	cp := make([]byte, len(*certPtr))
	copy(cp, *certPtr)
	return cp
}
