package grafana

import (
	"time"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/provider/httpproxy"
)

// DefaultGrafanaURL is the default Grafana Cloud API base URL.
// For self-hosted instances, configure grafana_url to point to your instance
// (e.g., https://grafana.example.com/api).
// For Grafana Cloud telemetry services, use the service-specific URL:
//   - Loki:      https://logs-prod-<region>.grafana.net
//   - Mimir:     https://prometheus-prod-<region>.grafana.net
//   - Tempo:     https://tempo-<region>.grafana.net
//   - Pyroscope: (found in your Grafana Cloud stack details)
const DefaultGrafanaURL = "https://grafana.com/api"

// DefaultGrafanaTimeout is the default request timeout for Grafana API calls
const DefaultGrafanaTimeout = 30 * time.Second

// Spec defines the Grafana provider configuration for the httpproxy framework.
//
// A single provider type supports all Grafana ecosystem services (dashboard API,
// Loki, Mimir, Tempo, Pyroscope) by mounting multiple instances with different
// grafana_url values. The optional tenant_id config injects the X-Scope-OrgID
// header required by Loki, Mimir, Tempo, and Pyroscope.
var Spec = &httpproxy.ProviderSpec{
	Name:               "grafana",
	DefaultURL:         DefaultGrafanaURL,
	URLConfigKey:       "grafana_url",
	DefaultTimeout:     DefaultGrafanaTimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-grafana-proxy",
	HelpText:           grafanaBackendHelp,
	ExtractCredentials: httpproxy.BearerAPIKeyExtractor,

	ExtraConfigFields: map[string]*framework.FieldSchema{
		"tenant_id": {
			Type:        framework.TypeString,
			Description: "Tenant/org ID injected as X-Scope-OrgID header (required for Loki, Mimir, Tempo, Pyroscope)",
		},
	},
	DynamicHeaders: func(state map[string]any) map[string]string {
		tenantID, _ := state["tenant_id"].(string)
		if tenantID == "" {
			return nil
		}
		return map[string]string{"X-Scope-OrgID": tenantID}
	},
	OnConfigRead: func(state map[string]any) map[string]any {
		tenantID, _ := state["tenant_id"].(string)
		return map[string]any{"tenant_id": tenantID}
	},
	OnConfigWrite: func(d *framework.FieldData, state map[string]any) (map[string]any, error) {
		if val, ok := d.GetOk("tenant_id"); ok {
			state["tenant_id"] = val.(string)
		}
		return state, nil
	},
	OnInitialize: func(config map[string]any, state map[string]any) map[string]any {
		if tid, ok := config["tenant_id"].(string); ok && tid != "" {
			state["tenant_id"] = tid
		}
		return state
	},
}

// Factory creates a new Grafana provider backend.
var Factory = httpproxy.NewFactory(Spec)

const grafanaBackendHelp = `
The Grafana provider enables proxying requests to Grafana REST APIs with
automatic credential management and token injection.

Warden performs implicit authentication on every request and obtains a
Grafana service account token (or Cloud access policy token) from the
credential manager, injecting it into the proxied request's Authorization
header.

This single provider type supports the entire Grafana ecosystem by mounting
multiple instances with different grafana_url values:

  Dashboard API:  grafana_url=https://<stack>.grafana.net/api
  Loki (logs):    grafana_url=https://logs-prod-<region>.grafana.net
  Mimir (metrics): grafana_url=https://prometheus-prod-<region>.grafana.net
  Tempo (traces): grafana_url=https://tempo-<region>.grafana.net

For Loki, Mimir, Tempo, and Pyroscope, set tenant_id in the config to
inject the X-Scope-OrgID header automatically.

The gateway path format is:
  /grafana/gateway/{api-path}

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /grafana/role/{role}/gateway/{api-path}

Example API paths (dashboard API):
  /grafana/gateway/org
  /grafana/gateway/dashboards/uid/{uid}
  /grafana/gateway/datasources
  /grafana/gateway/serviceaccounts/search
  /grafana/gateway/alertmanager/grafana/api/v2/alerts

Example API paths (Loki):
  /grafana-loki/gateway/loki/api/v1/query
  /grafana-loki/gateway/loki/api/v1/query_range
  /grafana-loki/gateway/loki/api/v1/labels
  /grafana-loki/gateway/loki/api/v1/push

Example API paths (Mimir):
  /grafana-mimir/gateway/api/v1/push
  /grafana-mimir/gateway/prometheus/api/v1/query
  /grafana-mimir/gateway/prometheus/api/v1/query_range

Credential source types:
- apikey: Static service account token or Cloud access policy token
- grafana: Dynamic service account tokens minted via the Grafana HTTP API

Configuration:
- grafana_url: Grafana API base URL (default: https://grafana.com/api)
- tenant_id: Tenant ID for X-Scope-OrgID header (required for Loki/Mimir/Tempo/Pyroscope)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
`
