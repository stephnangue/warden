package kubernetes

import (
	"context"
	"net/http"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

const maskedSecret = "*************"

// pathConfig returns the /config path definition.
func (b *kubernetesAuthBackend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"kubernetes_host": {
				Type:        framework.TypeString,
				Description: "kube-apiserver base URL, e.g. https://10.0.0.1:6443. Required.",
			},
			"kubernetes_ca_cert": {
				Type:        framework.TypeString,
				Description: "PEM-encoded CA bundle for kube-apiserver TLS validation. Required unless tls_skip_verify=true.",
			},
			"token_reviewer_jwt": {
				Type:        framework.TypeString,
				Description: "Optional hub-side service-account JWT used as the Authorization: Bearer for TokenReview calls. When unset, the workload's own JWT is used (self-reviewing mode; requires the workload SA to have system:auth-delegator).",
			},
			"tls_skip_verify": {
				Type:        framework.TypeBool,
				Description: "Disable TLS validation on TokenReview calls. Dev only.",
			},
			"issuer": {
				Type:        framework.TypeString,
				Description: "If set, login pre-filters on the workload JWT's iss claim matching this value before calling TokenReview.",
			},
			"disable_iss_validation": {
				Type:        framework.TypeBool,
				Description: "Skip the iss claim pre-filter even when issuer is non-empty.",
			},
			"token_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default TTL for issued tokens (default: 1h). Per-role token_ttl overrides this.",
			},
			"default_role": {
				Type:        framework.TypeString,
				Description: "Default role for transparent operations when no role is specified.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleConfigRead,
				Summary:  "Read kubernetes auth configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleConfigWrite,
				Summary:  "Configure kubernetes authentication",
			},
		},
		HelpSynopsis:    "Configure the kubernetes auth method",
		HelpDescription: `Configures the connection to the kube-apiserver used for TokenReview calls, plus optional issuer pinning and default-role for transparent mode. The token_reviewer_jwt is masked on read.`,
	}
}

// handleConfigRead returns the current configuration with token_reviewer_jwt
// masked. Fields not yet set are returned as their zero values.
func (b *kubernetesAuthBackend) handleConfigRead(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.configMu.RLock()
	defer b.configMu.RUnlock()

	if b.config == nil {
		return &logical.Response{StatusCode: http.StatusOK, Data: map[string]any{}}, nil
	}

	maskedReviewer := ""
	if b.config.TokenReviewerJWT != "" {
		maskedReviewer = maskedSecret
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"kubernetes_host":        b.config.KubernetesHost,
			"kubernetes_ca_cert":     b.config.KubernetesCACert,
			"token_reviewer_jwt":     maskedReviewer,
			"tls_skip_verify":        b.config.TLSSkipVerify,
			"issuer":                 b.config.Issuer,
			"disable_iss_validation": b.config.DisableIssValidation,
			"token_ttl":              b.config.TokenTTL.String(),
			"default_role":           b.config.DefaultRole,
		},
	}, nil
}

// handleConfigWrite merges the request fields with the existing config,
// runs setupConfig (which validates + rebuilds the HTTP client), then
// persists the normalized form to storage.
func (b *kubernetesAuthBackend) handleConfigWrite(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	conf := make(map[string]any)

	b.configMu.RLock()
	if b.config != nil {
		conf["kubernetes_host"] = b.config.KubernetesHost
		conf["kubernetes_ca_cert"] = b.config.KubernetesCACert
		conf["token_reviewer_jwt"] = b.config.TokenReviewerJWT
		conf["tls_skip_verify"] = b.config.TLSSkipVerify
		conf["issuer"] = b.config.Issuer
		conf["disable_iss_validation"] = b.config.DisableIssValidation
		conf["token_ttl"] = b.config.TokenTTL
		conf["default_role"] = b.config.DefaultRole
	}
	b.configMu.RUnlock()

	for key := range d.Schema {
		if val, ok := d.GetOk(key); ok {
			conf[key] = val
		}
	}

	if err := b.setupConfig(ctx, conf); err != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        err,
		}, nil
	}

	if b.storageView != nil {
		b.configMu.RLock()
		normalized := map[string]any{
			"kubernetes_host":        b.config.KubernetesHost,
			"kubernetes_ca_cert":     b.config.KubernetesCACert,
			"token_reviewer_jwt":     b.config.TokenReviewerJWT,
			"tls_skip_verify":        b.config.TLSSkipVerify,
			"issuer":                 b.config.Issuer,
			"disable_iss_validation": b.config.DisableIssValidation,
			"token_ttl":              b.config.TokenTTL.String(),
			"default_role":           b.config.DefaultRole,
		}
		b.configMu.RUnlock()

		entry, err := sdklogical.StorageEntryJSON("config", normalized)
		if err != nil {
			return &logical.Response{StatusCode: http.StatusInternalServerError, Err: err}, nil
		}
		if err := b.storageView.Put(ctx, entry); err != nil {
			return &logical.Response{StatusCode: http.StatusInternalServerError, Err: err}, nil
		}
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data:       map[string]any{"message": "configuration updated"},
	}, nil
}
