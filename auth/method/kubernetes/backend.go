// Package kubernetes implements the Warden auth method that validates
// workload tokens by calling the Kubernetes TokenReview API on the
// issuing kube-apiserver. Removes the JWKS-on-spoke requirement that
// hardened distros (Talos default, CIS-baseline) make awkward, and
// matches the auth/kubernetes shape Vault and OpenBao operators already
// know.
package kubernetes

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/helper/httputil"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// KubernetesAuthConfig is the per-mount configuration for the kubernetes
// auth method. Operator-authored via POST /config; persisted as JSON.
type KubernetesAuthConfig struct {
	// KubernetesHost is the kube-apiserver base URL, e.g. https://10.0.0.1:6443.
	// Required.
	KubernetesHost string `json:"kubernetes_host"`

	// KubernetesCACert is the PEM-encoded CA bundle Warden uses to validate
	// the kube-apiserver's TLS cert. Required unless TLSSkipVerify is true.
	KubernetesCACert string `json:"kubernetes_ca_cert,omitempty"`

	// TokenReviewerJWT is an optional hub-side service-account JWT used as
	// the Authorization: Bearer for TokenReview calls. When unset, the
	// auth method falls back to self-reviewing mode (the workload's own
	// JWT is used as the bearer; requires the workload SA to have
	// system:auth-delegator on the spoke cluster).
	//
	// Treated as a secret — masked on GET /config.
	TokenReviewerJWT string `json:"token_reviewer_jwt,omitempty"`

	// TLSSkipVerify disables TLS validation on TokenReview calls. Dev only.
	TLSSkipVerify bool `json:"tls_skip_verify,omitempty"`

	// Issuer, if set, gates login on the workload JWT's `iss` claim
	// matching this value (cheap unverified parse, before the TokenReview
	// round-trip). Per-mount issuer pinning is the right place to do this
	// — the introspect aggregator stays config-agnostic.
	Issuer string `json:"issuer,omitempty"`

	// DisableIssValidation lets operators opt out of the `iss` pre-filter
	// even when Issuer is non-empty.
	DisableIssValidation bool `json:"disable_iss_validation,omitempty"`

	// TokenTTL is the default TTL for issued Warden tokens; per-role
	// TokenTTL overrides this.
	TokenTTL time.Duration `json:"token_ttl" default:"1h"`

	// DefaultRole, if set, is used by transparent-mode flows when the
	// caller doesn't specify a role.
	DefaultRole string `json:"default_role,omitempty"`

	// Internal runtime state — derived from the stored config on Initialize.
	httpClient *http.Client `json:"-"`
}

// kubernetesAuthBackend is the framework-based kubernetes auth method.
type kubernetesAuthBackend struct {
	*framework.Backend
	config      *KubernetesAuthConfig
	configMu    sync.RWMutex
	logger      *logger.GatedLogger
	storageView sdklogical.Storage
}

var _ logical.Factory = Factory

// Factory creates a new kubernetes auth backend per the logical.Factory pattern.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &kubernetesAuthBackend{
		logger:      conf.Logger,
		storageView: conf.StorageView,
	}

	b.Backend = &framework.Backend{
		Help:         kubernetesAuthHelp,
		BackendType:  "kubernetes",
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
		},
	}

	if err := b.Backend.Setup(ctx, conf); err != nil {
		return nil, err
	}

	if len(conf.Config) > 0 {
		if err := b.setupConfig(ctx, conf.Config); err != nil {
			return nil, fmt.Errorf("failed to setup kubernetes config: %w", err)
		}
	}

	return b, nil
}

// setupConfig parses the operator-supplied config map, builds the HTTP
// client used for TokenReview calls, validates required fields, and
// installs the resulting KubernetesAuthConfig under the backend mutex.
func (b *kubernetesAuthBackend) setupConfig(_ context.Context, conf map[string]any) error {
	cfg, err := mapToKubernetesAuthConfig(conf)
	if err != nil {
		return err
	}

	if cfg.KubernetesHost == "" {
		return fmt.Errorf("kubernetes_host is required")
	}
	if cfg.KubernetesCACert == "" && !cfg.TLSSkipVerify {
		return fmt.Errorf("kubernetes_ca_cert is required unless tls_skip_verify is true")
	}

	client, err := buildKubernetesClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes HTTP client: %w", err)
	}
	cfg.httpClient = client

	b.configMu.Lock()
	b.config = cfg
	b.configMu.Unlock()
	return nil
}

// Initialize loads persisted config from storage and re-runs setupConfig
// so the in-memory HTTP client is rebuilt after a restart.
func (b *kubernetesAuthBackend) Initialize(ctx context.Context) error {
	if b.storageView == nil {
		return nil
	}
	entry, err := b.storageView.Get(ctx, "config")
	if err != nil {
		return fmt.Errorf("failed to read config from storage: %w", err)
	}
	if entry == nil {
		return nil
	}
	var configMap map[string]any
	if err := entry.DecodeJSON(&configMap); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}
	if err := b.setupConfig(ctx, configMap); err != nil {
		return fmt.Errorf("failed to setup kubernetes config from storage: %w", err)
	}
	return nil
}

// SensitiveConfigFields returns the config fields that should be masked
// on GET /config. token_reviewer_jwt is a hub-side service-account token
// and is treated as a secret; CA certs and host URLs are public material.
func (b *kubernetesAuthBackend) SensitiveConfigFields() []string {
	return []string{"token_reviewer_jwt"}
}

// buildKubernetesClient constructs the *http.Client used for TokenReview
// calls. Reuses helper/httputil so the TLS handling is consistent across
// HTTP-talking auth methods and credential drivers; accepts raw PEM
// directly (auth-method config is operator-authored, no base64 transport).
func buildKubernetesClient(cfg *KubernetesAuthConfig) (*http.Client, error) {
	return httputil.BuildHTTPClient([]byte(cfg.KubernetesCACert), cfg.TLSSkipVerify, defaultHTTPTimeout)
}

const kubernetesAuthHelp = `
The "kubernetes" auth method validates workload service-account tokens
by calling the Kubernetes TokenReview API on the issuing kube-apiserver.

Configure: kubernetes_host, kubernetes_ca_cert, optionally token_reviewer_jwt.
Roles bind to bound_service_account_names and bound_service_account_namespaces.
`
