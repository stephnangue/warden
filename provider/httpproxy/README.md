# httpproxy - Generic HTTP Proxy Provider Framework

The `httpproxy` package provides a configuration-driven framework for building Warden gateway providers. Instead of writing ~500 lines of boilerplate per provider, you define a `ProviderSpec` struct and get a fully functional provider in a single file.

## What you get for free

- Streaming gateway paths (`gateway`, `gateway/.*`, `role/[^/]+/gateway`, `role/[^/]+/gateway/.*`)
- Implicit authentication with role via header or URL path
- Config CRUD endpoint (`config`) with storage persistence
- HTTP reverse proxy with timeout and max body size enforcement
- Header sanitization (security, hop-by-hop, proxy headers)
- HTTP/2 transport with connection pooling and idle cleanup
- Config validation (URL, timeout, max_body_size, auto_auth_path, default_role)

## Quick start: simple API-key provider

Create a single file at `provider/<name>/provider.go`:

```go
package myprovider

import (
    "time"
    "github.com/stephnangue/warden/provider/httpproxy"
)

const (
    DefaultURL     = "https://api.myprovider.com"
    DefaultTimeout = 30 * time.Second
)

var (
    sharedTransport        = httpproxy.NewTransport()
    transportCleanupCancel = httpproxy.StartCleanup(sharedTransport)
)

var Spec = &httpproxy.ProviderSpec{
    Name:               "myprovider",
    DefaultURL:         DefaultURL,
    URLConfigKey:       "myprovider_url",
    DefaultTimeout:     DefaultTimeout,
    ParseStreamBody:    false,
    HelpText:           helpText,
    ExtractCredentials: httpproxy.BearerAPIKeyExtractor,
    Transport:          sharedTransport,
    ShutdownTransport: func() {
        httpproxy.ShutdownTransport(sharedTransport, transportCleanupCancel)
    },
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
- `warden provider enable --type=myprovider`
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
| `Transport` | Shared `*http.Transport` for this provider type. Create via `httpproxy.NewTransport()`. |
| `ShutdownTransport` | Cleanup function called during application shutdown. |

### Optional fields

| Field | Default | Description |
|-------|---------|-------------|
| `ParseStreamBody` | `false` | Enable request body parsing for policy evaluation (model, max_tokens, etc.). Set `true` for AI providers. |
| `UserAgent` | `"warden-{Name}-proxy"` | User-Agent header on proxied requests. |
| `ExtractToken` | `DefaultTokenExtractor` | Override how the Warden session token is extracted from incoming requests. |
| `ExtraHeadersToRemove` | `[]` | Provider-specific headers to strip beyond the [base set](#base-headers-removed). |
| `DefaultHeaders` | `nil` | Static headers always set on proxied requests (e.g., `{"anthropic-version": "2023-06-01"}`). |
| `DynamicHeaders` | `nil` | Function returning headers derived from config state. Called on every request. |
| `DefaultAccept` | `"application/json"` | Override the default Accept header. |
| `ExtraConfigFields` | `nil` | Additional config fields beyond the standard five. |
| `OnConfigRead` | `nil` | Add extra fields to config read response from provider state. |
| `OnConfigWrite` | `nil` | Process extra config fields during config write. |
| `OnInitialize` | `nil` | Load extra fields from persisted config during initialization. |
| `ValidateExtraConfig` | `nil` | Custom validation for provider-specific config fields. |

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

For providers with config beyond the standard five fields (url, max_body_size, timeout, auto_auth_path, default_role), use `ExtraConfigFields` with the state callbacks. See the GitHub provider for a complete example:

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
| Mistral | `BearerAPIKeyExtractor` | No | No |
| Slack | `BearerAPIKeyExtractor` | No | No |
| OpenAI | Custom (api_key + org + project) | No | No |
| Anthropic | `HeaderAPIKeyExtractor("x-api-key")` | Yes (x-api-key) | No |
| GitLab | `TypedTokenExtractor` | Yes (PRIVATE-TOKEN) | No |
| GitHub | `TypedTokenExtractor` | No | Yes (api_version) |
