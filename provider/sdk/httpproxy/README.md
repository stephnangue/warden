# httpproxy - Generic HTTP Proxy Provider Framework

The `httpproxy` package provides a configuration-driven framework for building Warden gateway providers. Instead of writing ~500 lines of boilerplate per provider, you define a `ProviderSpec` struct and get a fully functional provider in a single file.

## What you get for free

- Streaming gateway paths (`gateway`, `gateway/.*`, `role/[^/]+/gateway`, `role/[^/]+/gateway/.*`)
- Implicit authentication with role via header or URL path
- Config CRUD endpoint (`config`) with storage persistence
- HTTP reverse proxy with timeout and max body size enforcement
- Header sanitization (security, hop-by-hop, proxy headers)
- HTTP/2 transport with connection pooling and lazy initialization
- Config validation (URL, timeout, max_body_size, auto_auth_path, default_role)
- Optional per-request dispatch for multi-protocol providers (different upstream, credentials, header policy, or body cap per request)

## Quick start: simple API-key provider

Create a single file at `provider/<name>/provider.go`:

```go
package myprovider

import (
    "time"
    "github.com/stephnangue/warden/provider/sdk/httpproxy"
)

const (
    DefaultURL     = "https://api.myprovider.com"
    DefaultTimeout = 30 * time.Second
)

var Spec = &httpproxy.ProviderSpec{
    Name:               "myprovider",
    DefaultURL:         DefaultURL,
    URLConfigKey:       "myprovider_url",
    DefaultTimeout:     DefaultTimeout,
    ParseStreamBody:    false,
    HelpText:           helpText,
    ExtractCredentials: httpproxy.BearerAPIKeyExtractor,
}

var Factory = httpproxy.NewFactory(Spec)

const helpText = `
The myprovider provider proxies requests to the MyProvider API.

Gateway path format:
  /myprovider/gateway/{api-path}

Configuration:
- myprovider_url: API base URL (default: https://api.myprovider.com)
- max_body_size: Maximum request body size (default: 10MB, max: 100MB)
- timeout: Request timeout (default: 30s)
- auto_auth_path: Auth mount for implicit auth (e.g., 'auth/jwt/')
- default_role: Fallback role for implicit auth
`
```

Then register it in `cmd/server/server.go`:

```go
import "github.com/stephnangue/warden/provider/myprovider"

providers = map[string]wardenlogical.Factory{
    // ...existing providers...
    "myprovider": myprovider.Factory,
}
```

That's it. Your provider supports:
- `warden provider enable myprovider`
- `warden write myprovider/config myprovider_url=... auto_auth_path=auth/jwt/`
- `POST /myprovider/gateway/v1/some/endpoint` (role provided via `X-Warden-Role` header)
- `POST /myprovider/role/{role}/gateway/v1/some/endpoint` (role embedded in URL path)

Both paths perform implicit authentication and credential injection. The only difference is how the role is communicated: via the `X-Warden-Role` header or embedded in the URL path.

## ProviderSpec reference

### Required fields

| Field | Description |
|-------|-------------|
| `Name` | Provider identifier (e.g., `"datadog"`). Used for backend type, logging, and help text. |
| `DefaultURL` | Upstream API base URL (e.g., `"https://api.datadoghq.com"`). Set to `""` if the URL must be configured explicitly (like GitLab). |
| `URLConfigKey` | Config key for the upstream URL (e.g., `"datadog_url"`). Appears in config read/write. |
| `DefaultTimeout` | Default request timeout. Use `120 * time.Second` for AI inference, `30 * time.Second` for REST APIs. |
| `HelpText` | Backend help description shown in `warden path-help`. |
| `ExtractCredentials` | Function that extracts credentials from the request and returns headers to inject. See [Credential extractors](#credential-extractors). |

### Optional fields

| Field | Default | Description |
|-------|---------|-------------|
| `ParseStreamBody` | `false` | Enable request body parsing for policy evaluation. When `true`, the framework extracts fields like `model` and `max_tokens` from the JSON request body so access control policies can enforce per-model or per-parameter rules. Set `true` for AI providers (OpenAI, Anthropic, etc.), `false` for REST APIs. Providers carrying a non-JSON protocol on the side can set `true` and suppress parsing per request via `Dispatch.BypassBodyParsing` returned from `ResolveUpstream`. |
| `UserAgent` | `"warden-{Name}-proxy"` | User-Agent header on proxied requests. |
| `ExtractToken` | `DefaultTokenExtractor` | Override how the Warden session token is extracted from incoming requests. |
| `ExtraHeadersToRemove` | `[]` | Provider-specific headers to strip beyond the [base set](#base-headers-removed). |
| `DefaultHeaders` | `nil` | Static headers always set on proxied requests (e.g., `{"anthropic-version": "2023-06-01"}`). |
| `DynamicHeaders` | `nil` | Function returning headers derived from config state. Called on every request. Per-request dispatches can opt out via `Dispatch.SkipDynamicHeaders`. |
| `DefaultAccept` | `"application/json"` | Override the default Accept header. Per-request overrides are available via `Dispatch.Accept` and `Dispatch.SkipDefaultAccept`. |
| `ExtraConfigFields` | `nil` | Additional config fields beyond the standard five. |
| `OnConfigRead` | `nil` | Add extra fields to config read response from provider state. |
| `OnConfigWrite` | `nil` | Process extra config fields during config write. |
| `OnInitialize` | `nil` | Load extra fields from persisted config during initialization. |
| `ValidateExtraConfig` | `nil` | Custom validation for provider-specific config fields. |
| `NewTransport` | `DefaultNewTransport` | Factory returning `(*http.Transport, func())`. Called lazily on first instantiation. Override for custom transport settings. |
| `ResolveUpstream` | `nil` | Per-request override hook for upstream URL, credential extractor, Accept header, dynamic headers, body cap, and body parsing. Used by providers carrying multiple protocols on one mount. See [Per-request dispatch](#per-request-dispatch). |
| `GetAuthRoleFromRequest` | `nil` | Optional hook to derive the auth role from the HTTP request (e.g., Basic Auth username for Git smart-HTTP). Consulted after URL-path role lookup; `X-Warden-Role` header always wins. See [Custom role extraction](#custom-role-extraction). |

## Credential extractors

Built-in extractors cover common auth patterns:

### `BearerAPIKeyExtractor`

Extracts `api_key` from a `TypeAPIKey` credential, injects as `Authorization: Bearer {key}`.

```go
ExtractCredentials: httpproxy.BearerAPIKeyExtractor,
```

Used by: Mistral, Slack.

### `HeaderAPIKeyExtractor(headerName)`

Extracts `api_key` from a `TypeAPIKey` credential, injects into a custom header.

```go
ExtractCredentials: httpproxy.HeaderAPIKeyExtractor("x-api-key"),
```

Used by: Anthropic.

### `MultiFieldAPIKeyExtractor(requiredFields, optionalFields)`

Extracts multiple fields from a `TypeAPIKey` credential and maps them to headers. Required fields must be present; optional fields are included when non-empty.

```go
ExtractCredentials: httpproxy.MultiFieldAPIKeyExtractor(
    map[string]string{"api_key": "Authorization"},                                      // required
    map[string]string{"org_id": "OpenAI-Organization", "project_id": "OpenAI-Project"}, // optional
),
```

Used by: Datadog.

### `TypedTokenExtractor(credType, credField, headerName, headerPrefix)`

For non-APIKey credential types. Validates the credential type, extracts a field, and injects with an optional prefix.

```go
// GitHub: token field -> "Authorization: token {val}"
ExtractCredentials: httpproxy.TypedTokenExtractor(
    credential.TypeGitHubToken, "token", "Authorization", "token ",
)

// GitLab: access_token field -> "Authorization: Bearer {val}"
ExtractCredentials: httpproxy.TypedTokenExtractor(
    credential.TypeGitLabAccessToken, "access_token", "Authorization", "Bearer ",
)
```

### Custom extractor

For providers that need multiple credential fields or special logic:

```go
func myExtractor(req *logical.Request) (map[string]string, error) {
    if req.Credential == nil {
        return nil, fmt.Errorf("no credential available")
    }
    apiKey := req.Credential.Data["api_key"]
    appKey := req.Credential.Data["app_key"]
    if apiKey == "" {
        return nil, fmt.Errorf("credential missing api_key field")
    }
    headers := map[string]string{
        "DD-API-KEY": apiKey,
    }
    if appKey != "" {
        headers["DD-APPLICATION-KEY"] = appKey
    }
    return headers, nil
}
```

## Custom token extraction

By default, the Warden session token is extracted from `X-Warden-Token` or `Authorization: Bearer` headers. Override this if your provider's SDK sends tokens differently:

```go
// Anthropic clients send tokens via x-api-key header
func extractToken(r *http.Request) string {
    if token := r.Header.Get("X-Warden-Token"); token != "" {
        return token
    }
    if token := r.Header.Get("x-api-key"); token != "" {
        return token
    }
    // fallback to Bearer
    authHeader := r.Header.Get("Authorization")
    if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
        return authHeader[7:]
    }
    return ""
}

var Spec = &httpproxy.ProviderSpec{
    // ...
    ExtractToken: extractToken,
}
```

## Extra config fields

For providers with config beyond the standard seven fields (url, max_body_size, timeout, auto_auth_path, default_role, tls_skip_verify, ca_data), use `ExtraConfigFields` with the state callbacks. See the GitHub provider for a complete example:

```go
var Spec = &httpproxy.ProviderSpec{
    // ...
    ExtraConfigFields: map[string]*framework.FieldSchema{
        "api_version": {
            Type:        framework.TypeString,
            Description: "API version header value",
            Default:     "2022-11-28",
        },
    },
    DynamicHeaders: func(state map[string]any) map[string]string {
        ver, _ := state["api_version"].(string)
        if ver == "" { ver = "2022-11-28" }
        return map[string]string{"X-Api-Version": ver}
    },
    OnConfigRead: func(state map[string]any) map[string]any {
        ver, _ := state["api_version"].(string)
        if ver == "" { ver = "2022-11-28" }
        return map[string]any{"api_version": ver}
    },
    OnConfigWrite: func(d *framework.FieldData, state map[string]any) (map[string]any, error) {
        if val, ok := d.GetOk("api_version"); ok {
            state["api_version"] = val.(string)
        }
        return state, nil
    },
    OnInitialize: func(config map[string]any, state map[string]any) map[string]any {
        if ver, ok := config["api_version"].(string); ok && ver != "" {
            state["api_version"] = ver
        }
        return state
    },
}
```

## Per-request dispatch

A provider that serves a single protocol on a single upstream URL needs nothing here. A provider that carries **multiple protocols on the same mount** — e.g., GitHub's REST API and Git smart-HTTP, both rooted at `/github/gateway/...` — can route a subset of paths to a different upstream, with different credential formatting, header policy, and body cap, via `ResolveUpstream`.

`ResolveUpstream` is consulted once per gateway request, after the framework takes a read-lock snapshot of the mutable backend state and before credentials are extracted. The hook returns a `Dispatch` (the per-request override carrier) and a boolean. When the boolean is `false` — or when the hook is unset — the spec/mount defaults apply unchanged.

```go
type Dispatch struct {
    UpstreamURL        string              // overrides providerURL when non-empty
    ExtractCredentials CredentialExtractor // overrides Spec.ExtractCredentials when non-nil
    Accept             string              // overrides Spec.DefaultAccept when non-empty
    SkipDefaultAccept  bool                // suppress Accept injection entirely
    SkipDynamicHeaders bool                // disable Spec.DynamicHeaders for this request
    MaxBodySize        int64               // overrides per-mount max_body_size when > 0
    BypassBodyParsing  bool                // suppress request-body parsing for this request
}

ResolveUpstream func(r *http.Request, providerURL string, state map[string]any) (Dispatch, bool)
```

Every field of `Dispatch` is opt-in: zero values fall through to the spec/mount default. Returning `(Dispatch{}, false)` is the explicit "use defaults for this request" signal — REST callers in a multi-protocol provider should hit this branch so REST behaviour is unchanged.

**State contract.** The `state` map passed to the hook is the backend's `extraState` map after a read-lock snapshot — the same map populated by `OnInitialize`/`OnConfigWrite` and read by `DynamicHeaders`. The closure **must not** mutate it: concurrent writers replace the reference under the write lock, so in-place mutation here would race. `OnConfigWrite` writes against a clone, so reads from the live map are safe.

**`PathAfterGateway` helper.** Most dispatch logic inspects the path *after* the `gateway/` segment. The SDK exports `PathAfterGateway(path string) (string, bool)` to avoid re-implementing the strip rule:

```go
api, ok := httpproxy.PathAfterGateway(r.URL.Path)
if !ok {
    // input contained no /gateway segment — caller-defined fallback
}
```

**Example: GitHub Git smart-HTTP.** The GitHub provider's mount serves both the REST API (proxied to `api.github.com` with a Bearer token) and Git smart-HTTP clone/fetch/push (proxied to `github.com` with HTTP Basic Auth carrying the PAT as the password). REST and Git request shapes are dispatched per-request:

```go
func resolveGitUpstream(r *http.Request, providerURL string, state map[string]any) (httpproxy.Dispatch, bool) {
    api, _ := httpproxy.PathAfterGateway(r.URL.Path)
    if !isGitSmartHTTPPath(api) {
        return httpproxy.Dispatch{}, false // REST → spec defaults apply
    }
    maxBody, ok := state["git_max_body_size"].(int64)
    if !ok || maxBody <= 0 {
        maxBody = DefaultGitMaxBodySize
    }
    return httpproxy.Dispatch{
        UpstreamURL:        deriveGitURL(providerURL), // api.github.com → github.com
        ExtractCredentials: gitCredentialExtractor,    // Basic x-access-token:<PAT> on the upstream call to github.com
        SkipDefaultAccept:  true,                      // Git negotiates its own content types
        SkipDynamicHeaders: true,                      // X-GitHub-Api-Version is irrelevant for Git
        MaxBodySize:        maxBody,                   // raised for push payloads (default 2 GiB)
        BypassBodyParsing:  true,                      // binary pack-files, don't parse as JSON
    }, true
}

var Spec = &httpproxy.ProviderSpec{
    // ...
    ResolveUpstream: resolveGitUpstream,
}
```

`BypassBodyParsing` is honoured by the framework's request-aware body-parsing decision, which consults `ResolveUpstream` on every request before deciding whether to parse — so spec authors set `ParseStreamBody: true` on the spec and selectively suppress parsing per request via `Dispatch`.

See `provider/github/git.go` for the full implementation.

## Custom role extraction

Warden resolves the auth role for every gateway request from up to four sources. By default the framework consults the URL path (`/role/{name}/gateway/...`) and the mount's `default_role` config; providers that want to derive the role from somewhere else — e.g., an HTTP Basic Auth username carried by a non-Warden client — set `GetAuthRoleFromRequest`:

```go
GetAuthRoleFromRequest func(r *http.Request) string
```

The hook returns the resolved role, or `""` for "no contribution — fall through to the next source." Returning `""` is also the implicit behaviour when the hook is unset.

**Precedence (highest wins):**

1. `X-Warden-Role` HTTP header — unconditional override.
2. URL-path role segment (`/role/{name}/gateway/...`).
3. `GetAuthRoleFromRequest` hook.
4. Mount-level `default_role` config.

`X-Warden-Role` is applied *after* every other source has been consulted — it is the unconditional override, not an early-return.

**Example: GitHub Git smart-HTTP.** Git clients carry credentials as HTTP Basic Auth; the GitHub provider uses the username slot to carry the Warden role and the password slot to carry the Warden JWT:

```bash
git clone https://<role>:$JWT@<warden-addr>/v1/github/gateway/<owner>/<repo>.git
```

The hook extracts the role from the Basic Auth username, but only on Git smart-HTTP paths — REST callers are unaffected:

```go
func roleFromBasicAuthUser(r *http.Request) string {
    api, _ := httpproxy.PathAfterGateway(r.URL.Path)
    if !isGitSmartHTTPPath(api) {
        return "" // REST: fall through to default_role
    }
    user, _, _ := r.BasicAuth()
    return user
}

var Spec = &httpproxy.ProviderSpec{
    // ...
    GetAuthRoleFromRequest: roleFromBasicAuthUser,
}
```

See `provider/github/git.go` for the full implementation.

## Custom URL validation

By default, URLs are validated to require `https://` scheme. If your provider needs different validation (e.g., GitLab allows HTTP for development instances), use `ValidateExtraConfig`:

```go
var Spec = &httpproxy.ProviderSpec{
    // ...
    ValidateExtraConfig: func(conf map[string]any) error {
        addr, ok := conf["gitlab_address"].(string)
        if !ok || addr == "" {
            return fmt.Errorf("gitlab_address is required")
        }
        // Custom validation allowing http://
        parsed, err := url.Parse(addr)
        if err != nil {
            return fmt.Errorf("invalid gitlab_address: %w", err)
        }
        if parsed.Scheme != "https" && parsed.Scheme != "http" {
            return fmt.Errorf("gitlab_address must use http:// or https://")
        }
        return nil
    },
}
```

## Base headers removed

Every proxied request has these headers stripped before credential injection:

**Security:** `Authorization`, `X-Warden-Token`, `X-Warden-Role`

**Hop-by-hop:** `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `Te`, `Trailers`, `Transfer-Encoding`, `Upgrade`

**Proxy:** `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Real-Ip`, `Forwarded`

Add provider-specific headers via `ExtraHeadersToRemove` (e.g., `[]string{"x-api-key", "anthropic-version"}` for Anthropic).

## When NOT to use httpproxy

This framework is for standard HTTP reverse proxy providers. Do **not** use it for:

- **AWS** -- requires SigV4 request signing, not simple header injection
- **Azure** -- embeds the target host in the URL path (`/gateway/{host}/{path}`)
- **Vault** -- has unauthenticated paths and a different credential lifecycle

These providers have fundamentally different request handling and should remain as custom implementations.

## Existing providers using httpproxy

| Provider | Credential extractor | Custom token? | Extra config? |
|----------|---------------------|---------------|---------------|
| Anthropic | `HeaderAPIKeyExtractor("x-api-key")` | Yes | No |
| Cohere | `BearerAPIKeyExtractor` | No | No |
| Datadog | `MultiFieldAPIKeyExtractor` | No | No |
| Dynatrace | Custom | No | No |
| Elastic | Custom | Yes | Yes |
| GitHub | `TypedTokenExtractor` (REST) + custom Basic (Git) | Yes | Yes |
| GitLab | `TypedTokenExtractor` | Yes | No |
| Kubernetes | `TypedTokenExtractor` | Yes | No |
| Mistral | `BearerAPIKeyExtractor` | No | No |
| NewRelic | `HeaderAPIKeyExtractor("Api-Key")` | Yes | No |
| OpenAI | Custom | No | No |
| OVH | `BearerAPIKeyExtractor` | No | No |
| PagerDuty | `BearerAPIKeyExtractor` | No | No |
| ServiceNow | `BearerAPIKeyExtractor` | No | Yes |
| Slack | `BearerAPIKeyExtractor` | No | No |
| Splunk | `BearerAPIKeyExtractor` | Yes | Yes |
