package cert

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// CertAuthConfig represents certificate authentication configuration
type CertAuthConfig struct {
	Mode           string        `json:"mode,omitempty"`            // "x509" (default) or "spiffe"
	TrustedCAPEM   string        `json:"trusted_ca_pem"`            // PEM-encoded trusted CA certs
	PrincipalClaim string        `json:"principal_claim,omitempty"` // "cn" (default), "dns_san", "email_san", "uri_san", "serial"
	TokenTTL       time.Duration `json:"token_ttl" default:"1h"`    // Default token TTL
	RevocationMode string        `json:"revocation_mode,omitempty"` // "none" (default), "crl", "ocsp", "best_effort"
	CRLCacheTTL    string        `json:"crl_cache_ttl,omitempty"`   // CRL cache TTL (default: "1h")
	OCSPTimeout    string        `json:"ocsp_timeout,omitempty"`    // OCSP request timeout (default: "5s")
	DefaultRole    string        `json:"default_role,omitempty"`    // Default role for transparent operations

	// Internal — parsed CA pool
	caPool *x509.CertPool `json:"-"`
}

type certAuthBackend struct {
	*framework.Backend
	config            *CertAuthConfig
	configMu          sync.RWMutex
	logger            *logger.GatedLogger
	storageView       sdklogical.Storage
	revocationChecker *revocationChecker

	// spiffeBundleSet holds the per-trust-domain X.509 authorities used to verify
	// SVIDs in spiffe mode. Guarded by spiffeMu, separate from configMu.
	spiffeBundleSet *x509bundle.Set
	spiffeMu        sync.RWMutex

	// Spiffe Federation refresh loop (active-node only). fedCancel stops the goroutine;
	// the fed*Interval fields override the defaults and exist for tests.
	fedCancel         context.CancelFunc
	fedMu             sync.Mutex
	fedTickInterval   time.Duration
	fedMinRefresh     time.Duration
	fedDefaultRefresh time.Duration
}

// Auth mount modes. A mount operates in exactly one mode, fixed on its config.
const (
	modeX509   = "x509"   // classic PKI: CA pool + field matching
	modeSPIFFE = "spiffe" // SPIFFE X.509-SVID relying party
)

var _ logical.Factory = Factory

// Factory creates a new certificate auth backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &certAuthBackend{
		logger:      conf.Logger,
		storageView: conf.StorageView,
	}

	b.Backend = &framework.Backend{
		Help:         certAuthHelp,
		BackendType:  "cert",
		BackendClass: logical.ClassAuth,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
				"introspect/roles",
			},
		},
		Paths: []*framework.Path{
			b.pathLogin(),
			b.pathConfig(),
			b.pathRole(),
			b.pathRoleList(),
			b.pathIntrospect(),
			b.pathSPIFFETrustDomain(),
			b.pathSPIFFETrustDomainList(),
			b.pathSPIFFETrustDomainRefresh(),
		},
	}

	// Stop the federation refresh loop on unmount/seal (step-down is covered by
	// the active context passed to Initialize).
	b.Backend.Clean = func(context.Context) { b.stopFederationRefresh() }

	if err := b.Backend.Setup(ctx, conf); err != nil {
		return nil, err
	}

	if len(conf.Config) > 0 {
		if err := b.setupCertConfig(ctx, conf.Config); err != nil {
			return nil, fmt.Errorf("failed to setup cert config: %w", err)
		}
	}

	return b, nil
}

// validRevocationModes lists the allowed values for revocation_mode.
var validRevocationModes = []string{"", "none", "crl", "ocsp", "best_effort"}

// validPrincipalClaims lists the allowed values for principal_claim.
var validPrincipalClaims = []string{"cn", "dns_san", "email_san", "uri_san", "serial"}

func (b *certAuthBackend) setupCertConfig(_ context.Context, conf map[string]any) error {
	config, err := mapToCertAuthConfig(conf)
	if err != nil {
		return err
	}

	if config.Mode == "" {
		config.Mode = modeX509
	}
	if config.Mode != modeX509 && config.Mode != modeSPIFFE {
		return fmt.Errorf("invalid mode %q; must be one of: %s, %s", config.Mode, modeX509, modeSPIFFE)
	}

	if config.TokenTTL == 0 {
		config.TokenTTL = time.Hour
	}
	if config.PrincipalClaim == "" {
		config.PrincipalClaim = "cn"
	}
	// Backward compatibility: the "spiffe_id" principal claim was removed because
	// it pulled a spiffe:// URI from the certificate without validating it as an
	// SVID. A persisted value is coerced to "uri_san" (identical result for a
	// single-URI SVID) so existing mounts keep loading; real SPIFFE validation
	// now lives in a mount configured with mode=spiffe.
	if config.PrincipalClaim == "spiffe_id" {
		b.logger.Warn("principal_claim \"spiffe_id\" is deprecated and does not validate SPIFFE SVIDs; coercing to \"uri_san\" (use a mount with mode=spiffe for SPIFFE validation)")
		config.PrincipalClaim = "uri_san"
	}
	if !isValidPrincipalClaim(config.PrincipalClaim) {
		return fmt.Errorf("invalid principal_claim %q; must be one of: %v", config.PrincipalClaim, validPrincipalClaims)
	}

	// Validate revocation mode
	if !isValidRevocationMode(config.RevocationMode) {
		return fmt.Errorf("invalid revocation_mode %q; must be one of: none, crl, ocsp, best_effort", config.RevocationMode)
	}

	// Parse and validate CRL cache TTL
	crlCacheTTL := time.Hour // default
	if config.CRLCacheTTL != "" {
		d, err := time.ParseDuration(config.CRLCacheTTL)
		if err != nil {
			return fmt.Errorf("invalid crl_cache_ttl: %w", err)
		}
		crlCacheTTL = d
	}

	// Parse and validate OCSP timeout
	ocspTimeout := 5 * time.Second // default
	if config.OCSPTimeout != "" {
		d, err := time.ParseDuration(config.OCSPTimeout)
		if err != nil {
			return fmt.Errorf("invalid ocsp_timeout: %w", err)
		}
		ocspTimeout = d
	}

	// Parse trusted CA certificates
	if config.TrustedCAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(config.TrustedCAPEM)) {
			return fmt.Errorf("trusted_ca_pem contains no valid certificates")
		}
		config.caPool = pool
	}

	// Initialize revocation checker if revocation is enabled
	mode := config.RevocationMode
	if mode != "" && mode != "none" {
		b.revocationChecker = newRevocationChecker(crlCacheTTL, ocspTimeout)
	} else {
		b.revocationChecker = nil
	}

	b.configMu.Lock()
	b.config = config
	b.configMu.Unlock()
	return nil
}

func isValidRevocationMode(mode string) bool {
	for _, valid := range validRevocationModes {
		if mode == valid {
			return true
		}
	}
	return false
}

func isValidPrincipalClaim(claim string) bool {
	for _, valid := range validPrincipalClaims {
		if claim == valid {
			return true
		}
	}
	return false
}

// Initialize loads persisted config from storage
func (b *certAuthBackend) Initialize(ctx context.Context) error {
	if b.storageView == nil {
		return nil
	}

	entry, err := b.storageView.Get(ctx, "config")
	if err != nil {
		return fmt.Errorf("failed to read config from storage: %w", err)
	}
	if entry != nil {
		var configMap map[string]any
		if err := entry.DecodeJSON(&configMap); err != nil {
			return fmt.Errorf("failed to decode config: %w", err)
		}
		if err := b.setupCertConfig(ctx, configMap); err != nil {
			return fmt.Errorf("failed to setup cert config from storage: %w", err)
		}
	}

	// In spiffe mode, load the configured trust-domain bundles. Fail closed: if
	// the bundles cannot be loaded, the mount must not serve SPIFFE logins.
	if b.mountMode() == modeSPIFFE {
		if err := b.rebuildBundleSet(ctx); err != nil {
			return fmt.Errorf("failed to load SPIFFE trust bundles: %w", err)
		}
		// Initialize runs only on the active node; ctx is the active context, so
		// the refresh loop stops on step-down. It no-ops with no federated domains.
		b.startFederationRefresh(ctx)
	}
	return nil
}

// mountMode returns the configured mount mode, defaulting to x509 when unset.
func (b *certAuthBackend) mountMode() string {
	b.configMu.RLock()
	defer b.configMu.RUnlock()
	if b.config != nil && b.config.Mode != "" {
		return b.config.Mode
	}
	return modeX509
}

// SensitiveConfigFields returns the list of config fields that should be masked
func (b *certAuthBackend) SensitiveConfigFields() []string {
	return []string{
		"trusted_ca_pem",
	}
}

// principalClaimAllowedValues converts validPrincipalClaims to []interface{} for FieldSchema.AllowedValues
func principalClaimAllowedValues() []interface{} {
	values := make([]interface{}, len(validPrincipalClaims))
	for i, v := range validPrincipalClaims {
		values[i] = v
	}
	return values
}

// buildCAPool builds an x509.CertPool from the given PEM string.
// Used for role-specific CAs that override the global trusted CAs.
func buildCAPool(caPEM string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, fmt.Errorf("certificate PEM contains no valid certificates")
	}
	return pool, nil
}

// certFingerprint returns the hex-encoded SHA-256 fingerprint of a certificate's raw DER bytes.
func certFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

const certAuthHelp = `
The certificate auth method authenticates clients using TLS client certificates.

Clients present a certificate during the TLS handshake (direct mTLS) or via
a forwarding header from a trusted load balancer (X-Forwarded-Client-Cert or
X-SSL-Client-Cert).

The certificate is validated against trusted CAs configured globally or per-role.
Role constraints (allowed CNs, SANs, OUs, Organizations) further restrict which
certificates are accepted.

Configuration:
  POST /auth/{mount}/config      - Configure trusted CAs and defaults
  GET  /auth/{mount}/config      - Read current configuration
  POST /auth/{mount}/role/:name  - Create roles with certificate constraints
  POST /auth/{mount}/login       - Authenticate with a client certificate
`

// parsePEMCertificates returns the number of valid certificates in a PEM bundle
func parsePEMCertificates(pemData string) int {
	count := 0
	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			if _, err := x509.ParseCertificate(block.Bytes); err == nil {
				count++
			}
		}
	}
	return count
}
