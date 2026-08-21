package prometheus

import (
	"fmt"
	"net/http"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// DefaultPrometheusTimeout is the default request timeout for Prometheus API calls.
const DefaultPrometheusTimeout = 30 * time.Second

// Auth schemes a mount can be configured for. Which one a Prometheus deployment
// speaks is a property of that deployment — how the server was started — not of
// the credential brokered to it, so it lives in mount config beside the URL that
// determines it.
const (
	authTypeBearer = "bearer"
	authTypeBasic  = "basic"
)

// prometheusExtractor injects the brokered key into Authorization under the
// mount's configured scheme.
//
//   - bearer (default) → Authorization: Bearer <api_key>
//     Used for: managed Prometheus services (Grafana Mimir, Amazon Managed
//     Prometheus, Thanos, Cortex) that accept bearer tokens.
//
//   - basic → Authorization: Basic <api_key>
//     api_key must be the base64-encoded "username:password" string.
//     Used for: self-hosted Prometheus with --web.config.file basic auth.
func prometheusExtractor(scheme string) httpproxy.CredentialExtractor {
	return func(req *logical.Request) (map[string]string, error) {
		if req.Credential == nil {
			return nil, fmt.Errorf("no credential available")
		}
		if req.Credential.Type != credential.TypeAPIKey {
			return nil, fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
		}
		apiKey := req.Credential.Data["api_key"]
		if apiKey == "" {
			return nil, fmt.Errorf("credential missing api_key field")
		}
		if scheme == authTypeBasic {
			return map[string]string{"Authorization": "Basic " + apiKey}, nil
		}
		return map[string]string{"Authorization": "Bearer " + apiKey}, nil
	}
}

// validateAuthType rejects anything but the two schemes. Enforced by hand in
// both write paths because framework.FieldSchema.AllowedValues is documentation
// only — it reaches the OpenAPI document and nothing else — so a typo would
// otherwise be stored and silently read back as bearer.
func validateAuthType(v string) error {
	switch v {
	case "", authTypeBearer, authTypeBasic:
		return nil
	default:
		return fmt.Errorf("auth_type must be %q or %q, got %q", authTypeBearer, authTypeBasic, v)
	}
}

// stateAuthType returns the mount's configured scheme, defaulting to bearer.
func stateAuthType(state map[string]any) string {
	if s, _ := state["auth_type"].(string); s != "" {
		return s
	}
	return authTypeBearer
}

// Spec defines the Prometheus provider configuration for the httpproxy framework.
//
// Prometheus has no universal API endpoint — every deployment has its own URL.
// Operators must set prometheus_url in the provider config. A single provider
// type supports vanilla Prometheus and all Prometheus-compatible services
// (Grafana Mimir, Amazon Managed Prometheus, Thanos, Cortex, VictoriaMetrics)
// by mounting multiple instances with different prometheus_url values.
var Spec = &httpproxy.ProviderSpec{
	Name:            "prometheus",
	URLConfigKey:    "prometheus_url",
	DefaultTimeout:  DefaultPrometheusTimeout,
	ParseStreamBody: true,
	UserAgent:       "warden-prometheus-proxy",
	HelpText:        prometheusBackendHelp,

	// Defensive default. ResolveUpstream always supplies a state-derived
	// extractor, so this is never consulted; it only guards against a nil-func
	// call if that ever changes.
	ExtractCredentials: prometheusExtractor(authTypeBearer),

	ExtraConfigFields: map[string]*framework.FieldSchema{
		"auth_type": {
			Type:          framework.TypeString,
			Default:       authTypeBearer,
			AllowedValues: []interface{}{authTypeBearer, authTypeBasic},
			Description:   "Authorization scheme the upstream speaks: bearer (default) or basic",
		},
	},

	ResolveUpstream: func(_ *http.Request, _ string, state map[string]any) (httpproxy.Dispatch, bool) {
		return httpproxy.Dispatch{ExtractCredentials: prometheusExtractor(stateAuthType(state))}, true
	},

	OnConfigWrite: func(d *framework.FieldData, state map[string]any) (map[string]any, error) {
		if v, ok := d.GetOk("auth_type"); ok {
			s := v.(string)
			if err := validateAuthType(s); err != nil {
				return nil, err
			}
			state["auth_type"] = s
		}
		return state, nil
	},

	OnConfigRead: func(state map[string]any) map[string]any {
		return map[string]any{"auth_type": stateAuthType(state)}
	},

	OnInitialize: func(config map[string]any, state map[string]any) map[string]any {
		if v, ok := config["auth_type"].(string); ok && v != "" {
			state["auth_type"] = v
		}
		return state
	},

	ValidateExtraConfig: func(conf map[string]any) error {
		v, _ := conf["auth_type"].(string)
		return validateAuthType(v)
	},
}

// Factory creates a new Prometheus provider backend.
var Factory = httpproxy.NewFactory(Spec)

const prometheusBackendHelp = `
The Prometheus provider enables proxying requests to the Prometheus HTTP API
with automatic credential management and auth header injection.

Warden performs implicit authentication on every request and obtains a
Prometheus credential from the credential manager, injecting it into the
proxied request's Authorization header. Which scheme it uses is a property of
the deployment, so it is set on the mount alongside prometheus_url:

  Bearer (default, auth_type=bearer):
    Used for managed Prometheus services (Grafana Mimir, Amazon Managed
    Prometheus, Thanos, Cortex, VictoriaMetrics) that accept bearer tokens.

  Basic Auth (auth_type=basic):
    Used for self-hosted Prometheus instances configured with
    --web.config.file basic auth. api_key must be the base64-encoded
    "username:password" string (e.g. base64("admin:secret")).

  Two deployments needing different schemes are two mounts, which they already
  had to be: each has its own prometheus_url.

This provider type supports the full Prometheus ecosystem by mounting
multiple instances with different prometheus_url values:

  Vanilla Prometheus:          prometheus_url=https://prometheus.example.com
  Grafana Mimir (remote):      prometheus_url=https://prometheus-prod-<region>.grafana.net/prometheus
  Amazon Managed Prometheus:   prometheus_url=https://aps-workspaces.<region>.amazonaws.com/workspaces/<id>
  Thanos Querier:              prometheus_url=https://thanos.example.com
  VictoriaMetrics:             prometheus_url=https://victoriametrics.example.com

Prometheus has no universal base URL — prometheus_url is required.

The gateway path format is:
  /prometheus/gateway/{api-path}

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /prometheus/role/{role}/gateway/{api-path}

Example API paths:
  /prometheus/gateway/api/v1/query
  /prometheus/gateway/api/v1/query_range
  /prometheus/gateway/api/v1/series
  /prometheus/gateway/api/v1/labels
  /prometheus/gateway/api/v1/label/<name>/values
  /prometheus/gateway/api/v1/targets
  /prometheus/gateway/api/v1/rules
  /prometheus/gateway/api/v1/alerts
  /prometheus/gateway/api/v1/status/config
  /prometheus/gateway/-/healthy
  /prometheus/gateway/-/ready

Credential source type:
- apikey: Static bearer token or pre-encoded basic auth credentials.

Configuration:
- prometheus_url: Prometheus API base URL (required — no universal default)
- auth_type: Authorization scheme the upstream speaks: bearer (default) or basic
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
