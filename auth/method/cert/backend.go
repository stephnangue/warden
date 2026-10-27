package cert

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// CertAuthConfig represents certificate authentication configuration
type CertAuthConfig struct {
	TrustedCAPEM   string        `json:"trusted_ca_pem"`            // PEM-encoded trusted CA certs
	PrincipalClaim string        `json:"principal_claim,omitempty"` // "cn" (default), "dns_san", "email_san", "uri_san", "serial"
	TokenTTL       time.Duration `json:"token_ttl" default:"1h"`    // Default token TTL
	RevocationMode string        `json:"revocation_mode,omitempty"` // "none" (default), "crl", "ocsp", "best_effort"
	CRLCacheTTL    string        `json:"crl_cache_ttl,omitempty"`   // CRL cache TTL (default: "1h")
	OCSPTimeout    string        `json:"ocsp_timeout,omitempty"`    // OCSP request timeout (default: "5s")

	// removed names the removed keys (helper.RemovedConfigKeys) the config
	// was built from, which it ignores; a config read warns about each.
	removed []string

	// Facts: entity_kind, and the certificate fields the mount publishes
	// under other names beyond its built-in facts. Compiled in
	// buildCertConfig. A config write refuses facts that do not compile, so
	// they are never stored; ones that still fail at load (the mount table's,
	// or storage written under looser rules) are installed with a nil naming:
	// the mount answers no fact, so nothing that reads facts can match it.
	helper.FactsConfig

	// Internal — parsed CA pool
	caPool *x509.CertPool `json:"-"`
	// Internal — revocation checker for RevocationMode, nil when it is off.
	// Held here so it is installed with the mode it serves.
	revocationChecker *revocationChecker `json:"-"`
}

type certAuthBackend struct {
	*framework.Backend
	// config is replaced whole, never modified in place, so a reader may keep
	// the pointer it took under configMu after releasing the lock.
	config   *CertAuthConfig
	configMu sync.RWMutex
	// configWriteMu serializes config writes and the storage load: a write
	// merges onto the live config, so two racing would lose one writer's keys.
	configWriteMu sync.Mutex
	logger        *logger.GatedLogger
	storageView   sdklogical.Storage

	// mountFacts holds the naming in force and is shared by pointer with
	// every admission this mount produces. installConfig publishes it under
	// configMu together with the config it was compiled from, so a reader
	// holding configMu sees the two agree; admissions and FactNames load it
	// without a lock and see one published naming, whole.
	mountFacts *logical.MountFacts
}

var _ logical.Factory = Factory

// Factory creates a new certificate auth backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &certAuthBackend{
		logger:      conf.Logger,
		storageView: conf.StorageView,
		mountFacts:  &logical.MountFacts{},
	}

	b.Backend = &framework.Backend{
		Help:         certAuthHelp,
		BackendType:  "cert",
		BackendClass: logical.ClassAuth,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
		},
		Paths: append([]*framework.Path{
			b.pathLogin(),
			b.pathConfig(),
			helper.AdmitPath(b.admit),
		}, pathRoles()...),
	}

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

// setupCertConfig builds conf and installs it. It serves the mount table's
// config when the mount is set up and the stored config when it is loaded,
// which a failure here would turn into a failed mount (and, at unseal, a
// failed unseal). Facts that do not compile are therefore logged and installed
// as a nil naming, which answers no fact: closed for every reader of facts,
// while logins and the config itself keep working.
func (b *certAuthBackend) setupCertConfig(ctx context.Context, conf map[string]any) error {
	config, err := buildCertConfig(ctx, conf)
	if err != nil {
		return err
	}
	if err := config.FactsConfig.Err(); err != nil {
		b.logger.Error(helper.FactsDoNotCompileLog, logger.Err(err))
	}
	if len(config.removed) > 0 {
		b.logger.Warn("auth mount config sets removed keys, which are ignored", logger.Any("keys", config.removed))
	}
	b.installConfig(config)
	return nil
}

// installConfig makes config the live configuration and publishes its naming
// (nil when it does not compile, which answers no fact) in the same critical
// section. It cannot fail.
func (b *certAuthBackend) installConfig(config *CertAuthConfig) {
	b.configMu.Lock()
	b.config = config
	b.mountFacts.Publish(config.Naming())
	b.configMu.Unlock()
}

// buildCertConfig parses and validates conf into a configuration ready to
// install, without touching the backend.
func buildCertConfig(_ context.Context, conf map[string]any) (*CertAuthConfig, error) {
	config, err := mapToCertAuthConfig(conf)
	if err != nil {
		return nil, err
	}
	config.removed = helper.RemovedConfigKeys(conf)

	if config.TokenTTL == 0 {
		config.TokenTTL = time.Hour
	}
	if config.PrincipalClaim == "" {
		config.PrincipalClaim = "cn"
	}
	if !isValidPrincipalClaim(config.PrincipalClaim) {
		return nil, fmt.Errorf("invalid principal_claim %q; must be one of: %v", config.PrincipalClaim, validPrincipalClaims)
	}

	// Validate revocation mode
	if !isValidRevocationMode(config.RevocationMode) {
		return nil, fmt.Errorf("invalid revocation_mode %q; must be one of: none, crl, ocsp, best_effort", config.RevocationMode)
	}

	// Parse and validate CRL cache TTL
	crlCacheTTL := time.Hour // default
	if config.CRLCacheTTL != "" {
		d, err := time.ParseDuration(config.CRLCacheTTL)
		if err != nil {
			return nil, fmt.Errorf("invalid crl_cache_ttl: %w", err)
		}
		crlCacheTTL = d
	}

	// Parse and validate OCSP timeout
	ocspTimeout := 5 * time.Second // default
	if config.OCSPTimeout != "" {
		d, err := time.ParseDuration(config.OCSPTimeout)
		if err != nil {
			return nil, fmt.Errorf("invalid ocsp_timeout: %w", err)
		}
		ocspTimeout = d
	}

	// Parse trusted CA certificates
	if config.TrustedCAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(config.TrustedCAPEM)) {
			return nil, fmt.Errorf("trusted_ca_pem contains no valid certificates")
		}
		config.caPool = pool
	}

	// Initialize revocation checker if revocation is enabled
	if mode := config.RevocationMode; mode != "" && mode != "none" {
		config.revocationChecker = newRevocationChecker(crlCacheTTL, ocspTimeout)
	}

	// Facts that do not compile are kept on the config, not returned: the
	// caller decides whether to refuse them or fail closed.
	config.CompileFields(certBuiltinFacts(), certAliasPolicy)

	return config, nil
}

// normalizedCertConfig is config in the form storage holds, so that on restart
// the parser always sees consistent types (e.g., token_ttl is always a
// duration string, never a raw int from an HTTP request).
func normalizedCertConfig(config *CertAuthConfig) map[string]any {
	return map[string]any{
		"trusted_ca_pem":    config.TrustedCAPEM,
		"principal_claim":   config.PrincipalClaim,
		"token_ttl":         config.TokenTTL.String(),
		"revocation_mode":   config.RevocationMode,
		"crl_cache_ttl":     config.CRLCacheTTL,
		"ocsp_timeout":      config.OCSPTimeout,
		"entity_kind":       config.EntityKind,
		"facts":             config.Facts,
		"alias_name_source": config.AliasNameSource,
	}
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

	// The mount is routed before it is initialized, so a config write can
	// already be under way; loading storage over it would undo it.
	b.configWriteMu.Lock()
	defer b.configWriteMu.Unlock()

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
	return nil
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
func buildCAPool(caPEM string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, fmt.Errorf("certificate PEM contains no valid certificates")
	}
	return pool, nil
}

// certFingerprint returns the hex-encoded SHA-256 fingerprint of a certificate's raw DER bytes.
func certFingerprint(cert *x509.Certificate) string { return helper.CertFingerprint(cert) }

const certAuthHelp = `
The certificate auth method authenticates clients using TLS client certificates.

Clients present a certificate during the TLS handshake (direct mTLS) or via
a forwarding header from a trusted load balancer (X-Forwarded-Client-Cert or
X-SSL-Client-Cert).

The certificate is validated against the trusted CAs the mount configures.

Configuration:
  POST /auth/{mount}/config      - Configure trusted CAs and defaults
  GET  /auth/{mount}/config      - Read current configuration
  POST /auth/{mount}/login       - Authenticate with a client certificate

The mount's entity_kind and facts name what it admits.
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
