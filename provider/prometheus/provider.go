package prometheus

import (
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
)

// DefaultPrometheusTimeout is the default request timeout for Prometheus API calls.
const DefaultPrometheusTimeout = 30 * time.Second

// prometheusExtractor injects credentials as Bearer or Basic Auth depending on
// the auth_type field in the credential data:
//
//   - auth_type=basic → Authorization: Basic <api_key>
//     api_key must be the base64-encoded "username:password" string.
//     Used for: self-hosted Prometheus with --web.config.file basic auth.
//
//   - auth_type=bearer (or unset) → Authorization: Bearer <api_key>
//     Used for: managed Prometheus services (Grafana Mimir, Amazon Managed
//     Prometheus, Thanos, Cortex) that accept bearer tokens.
//
// To forward the auth_type field from a spec config into credential data,
// configure the apikey source with optional_metadata=auth_type.
func prometheusExtractor(req *logical.Request) (map[string]string, error) {
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
	if req.Credential.Data["auth_type"] == "basic" {
		return map[string]string{"Authorization": "Basic " + apiKey}, nil
	}
	return map[string]string{"Authorization": "Bearer " + apiKey}, nil
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
	ExtractCredentials: prometheusExtractor,
}

// Factory creates a new Prometheus provider backend.
var Factory = httpproxy.NewFactory(Spec)

const prometheusBackendHelp = `
The Prometheus provider enables proxying requests to the Prometheus HTTP API
with automatic credential management and auth header injection.

Warden performs implicit authentication on every request and obtains a
Prometheus credential from the credential manager, injecting it into the
proxied request. Auth mode is detected automatically from the credential data:

  Bearer (default, auth_type=bearer or unset):
    Used for managed Prometheus services (Grafana Mimir, Amazon Managed
    Prometheus, Thanos, Cortex, VictoriaMetrics) that accept bearer tokens.

  Basic Auth (auth_type=basic):
    Used for self-hosted Prometheus instances configured with
    --web.config.file basic auth. api_key must be the base64-encoded
    "username:password" string (e.g. base64("admin:secret")).
    Configure your apikey source with optional_metadata=auth_type and
    set auth_type=basic on the credential spec.

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
  For basic auth, set optional_metadata=auth_type on the source and
  include auth_type=basic in the spec config.

Configuration:
- prometheus_url: Prometheus API base URL (required — no universal default)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
