package kubernetes

import (
	"context"
	"maps"
	"net/http"
	"slices"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

const maskedSecret = "*************"

// pathConfig returns the /config path definition.
func (b *kubernetesAuthBackend) pathConfig() *framework.Path {
	fields := map[string]*framework.FieldSchema{
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
			Description: "TTL of issued tokens (default: 1h), capped by the workload token's expiry.",
		},
		"bound_audiences": {
			Type: framework.TypeCommaStringSlice,
			Description: "Audiences a workload token must carry, any one of them, sent to TokenReview as spec.audiences. " +
				"No entry may be empty; an empty value clears the list.",
		},
		"max_age": helper.MaxAgeFieldSchema(),
	}
	maps.Copy(fields, helper.FactsFieldSchemas(factsSources))

	return &framework.Path{
		Pattern: "config",
		Fields:  fields,
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
		HelpSynopsis: "Configure the kubernetes auth method",
		HelpDescription: `Configures the connection to the kube-apiserver used for TokenReview calls, plus optional issuer pinning. The token_reviewer_jwt is masked on read.

'entity_kind' (agent or human, default agent) names what the mount admits.
'facts' maps TokenReview fields to the fact names the mount publishes beyond its
built-in facts (service_account_namespace, service_account_name,
service_account_uid, username, groups, aud); a write replaces the whole map.
'bound_audiences' are the audiences each TokenReview checks; when empty, the
API server checks its own audience.
'max_age' bounds a workload token's age at admission, from its iat: a token
older than it, or without an iat, is not admitted.`,
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

	warnings := helper.RemovedConfigWarnings(b.config.removed)
	if len(b.config.BoundAudiences) == 0 {
		warnings = append(warnings, noAudiencesWarning)
	}

	data := map[string]any{
		"kubernetes_host":        b.config.KubernetesHost,
		"kubernetes_ca_cert":     b.config.KubernetesCACert,
		"token_reviewer_jwt":     maskedReviewer,
		"tls_skip_verify":        b.config.TLSSkipVerify,
		"issuer":                 b.config.Issuer,
		"disable_iss_validation": b.config.DisableIssValidation,
		"token_ttl":              b.config.TokenTTL.String(),
		"bound_audiences":        slices.Clone(b.config.BoundAudiences),
		"max_age":                b.config.MaxAge.String(),
		"entity_kind":            b.config.EntityKind,
		"facts":                  maps.Clone(b.config.Facts),
	}
	helper.SetWarnings(data, warnings)
	return &logical.Response{StatusCode: http.StatusOK, Data: data}, nil
}

// handleConfigWrite merges the request fields with the existing config,
// runs buildConfig (which validates + rebuilds the HTTP client), persists
// the normalized form to storage, and only then installs it — so a write
// that is refused or cannot be stored leaves the mount authenticating
// against what storage holds. Writes are serialized, so each merges onto
// the configuration the previous one left.
func (b *kubernetesAuthBackend) handleConfigWrite(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configWriteMu.Lock()
	defer b.configWriteMu.Unlock()

	// Keys of the role era are refused, not ignored: the write would otherwise
	// succeed while doing nothing the operator asked for. The stored config
	// never carries them, so this write also removes any it still did.
	if err := helper.RefuseRemovedConfigKeys(d.Raw); err != nil {
		return logical.ErrorResponse(err), nil
	}

	conf := make(map[string]any)

	_, factsSent := d.GetOk("facts")
	_, kindSent := d.GetOk("entity_kind")
	factsTouched := factsSent || kindSent

	b.configMu.RLock()
	if b.config != nil {
		// Stored facts that do not compile would fail a write that leaves
		// them in place, whatever else it changes; say how to replace them.
		if !factsTouched {
			if err := helper.FactsWriteError(&b.config.FactsConfig, false); err != nil {
				b.configMu.RUnlock()
				return &logical.Response{
					StatusCode: http.StatusBadRequest,
					Err:        err,
				}, nil
			}
		}
		conf["kubernetes_host"] = b.config.KubernetesHost
		conf["kubernetes_ca_cert"] = b.config.KubernetesCACert
		conf["token_reviewer_jwt"] = b.config.TokenReviewerJWT
		conf["tls_skip_verify"] = b.config.TLSSkipVerify
		conf["issuer"] = b.config.Issuer
		conf["disable_iss_validation"] = b.config.DisableIssValidation
		conf["token_ttl"] = b.config.TokenTTL
		conf["bound_audiences"] = b.config.BoundAudiences
		conf["max_age"] = b.config.MaxAge
		conf["entity_kind"] = b.config.EntityKind
		conf["facts"] = b.config.Facts
	}
	b.configMu.RUnlock()

	for key := range d.Schema {
		if val, ok := d.GetOk(key); ok {
			conf[key] = val
		}
	}

	// A facts write replaces the whole mapping; every name must be a string.
	if raw, ok := d.GetOk("facts"); ok {
		facts, err := helper.ParseFactsField(raw)
		if err != nil {
			return &logical.Response{
				StatusCode: http.StatusBadRequest,
				Err:        err,
			}, nil
		}
		conf["facts"] = facts
	}

	cfg, err := buildConfig(ctx, conf)
	if err != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        err,
		}, nil
	}
	// A write is the one place facts can be refused outright; storage and
	// load only ever see a config that compiled here.
	if err := helper.FactsWriteError(&cfg.FactsConfig, factsTouched); err != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        err,
		}, nil
	}

	if b.storageView != nil {
		entry, err := sdklogical.StorageEntryJSON("config", normalizedConfig(cfg))
		if err != nil {
			return &logical.Response{StatusCode: http.StatusInternalServerError, Err: err}, nil
		}
		if err := b.storageView.Put(ctx, entry); err != nil {
			return &logical.Response{StatusCode: http.StatusInternalServerError, Err: err}, nil
		}
	}

	b.installConfig(cfg)

	// The write warns as the read does, so the operator sees it when acting.
	data := map[string]any{"message": "configuration updated"}
	if len(cfg.BoundAudiences) == 0 {
		helper.SetWarnings(data, []string{noAudiencesWarning})
	}
	return &logical.Response{StatusCode: http.StatusOK, Data: data}, nil
}
