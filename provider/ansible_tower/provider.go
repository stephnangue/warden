package ansible_tower

import (
	"fmt"
	"time"

	"github.com/stephnangue/warden/provider/httpproxy"
)

// DefaultAnsibleTowerTimeout is the default request timeout for Ansible Tower API calls
const DefaultAnsibleTowerTimeout = 30 * time.Second

// Spec defines the Ansible Tower provider configuration for the httpproxy framework.
var Spec = &httpproxy.ProviderSpec{
	Name:               "ansible_tower",
	DefaultURL:         "", // Instance-specific, must be configured
	URLConfigKey:       "ansible_tower_url",
	DefaultTimeout:     DefaultAnsibleTowerTimeout,
	ParseStreamBody:    true,
	UserAgent:          "warden-ansible-tower-proxy",
	HelpText:           ansibleTowerBackendHelp,
	ExtractCredentials: httpproxy.BearerAPIKeyExtractor,
	ValidateExtraConfig: func(conf map[string]any) error {
		addr, ok := conf["ansible_tower_url"].(string)
		if !ok || addr == "" {
			return fmt.Errorf("ansible_tower_url is required")
		}
		return nil
	},
}

// Factory creates a new Ansible Tower provider backend.
var Factory = httpproxy.NewFactory(Spec)

const ansibleTowerBackendHelp = `
The Ansible Tower provider enables proxying requests to the Ansible Tower
(AWX / Red Hat Ansible Automation Platform) REST API with automatic
credential management and bearer token injection.

Warden performs implicit authentication on every request and obtains an
Ansible Tower Personal Access Token (PAT) or OAuth2 token from the
credential manager, injecting it into the proxied request's Authorization
header. This allows Warden to broker Ansible Tower access without exposing
tokens to clients.

The gateway path format is:
  /ansible_tower/gateway/{api-path}

Examples:
  /ansible_tower/gateway/api/v2/ping/
  /ansible_tower/gateway/api/v2/me/
  /ansible_tower/gateway/api/v2/job_templates/
  /ansible_tower/gateway/api/v2/jobs/
  /ansible_tower/gateway/api/v2/inventories/
  /ansible_tower/gateway/api/v2/projects/
  /ansible_tower/gateway/api/v2/hosts/
  /ansible_tower/gateway/api/v2/workflow_job_templates/

The role can be provided via the X-Warden-Role header, or embedded in
the URL path:
  /ansible_tower/role/{role}/gateway/{api-path}

Request body parsing is enabled, allowing policies to evaluate Ansible
Tower request fields for fine-grained access control.

Two credential source types are supported:
- apikey: Static Personal Access Token (stored in spec config as api_key)
- hvault: Vault/OpenBao KV v2 secret containing api_key; use
  mint_method=static_apikey on the spec

Configuration:
- ansible_tower_url: Ansible Tower base URL (required, must use HTTPS,
  e.g., "https://tower.example.com")
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout duration (default: 30s)
- auto_auth_path: Auth mount path for implicit authentication (e.g., 'auth/jwt/')
- default_role: Fallback role when not specified in the URL path
- tls_skip_verify: Skip TLS certificate verification (for self-signed certs)
- ca_data: Base64-encoded PEM CA certificate for custom trust

The ansible_tower_url should point to your Ansible Tower or AWX instance,
for example:
  AWX:           https://awx.example.com
  AAP (direct):  https://controller.example.com
  AAP (gateway): https://aap.example.com
`
