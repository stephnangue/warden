# httpproxy - Generic HTTP Proxy Provider Framework

The `httpproxy` package provides a configuration-driven framework for building Warden gateway providers. Instead of writing ~500 lines of boilerplate per provider, you define a `ProviderSpec` struct and get a fully functional provider in a single file.

## What you get for free

- Streaming gateway paths (`gateway`, `gateway/.*`, `role/[^/]+/gateway`, `role/[^/]+/gateway/.*`)
- Implicit authentication with role via header or URL path, and an optional second (user) principal via `user_auth_path`
- Config CRUD endpoint (`config`) with storage persistence; a write validates, persists, then applies, so a rejected write changes nothing
- HTTP reverse proxy with a per-mount timeout (overridable per request via `SelectTimeout`) that also bounds the wait for response headers, and max body size enforcement
- Header sanitization (security, hop-by-hop, proxy headers)
- HTTP/2 transport with connection pooling and lazy initialization
- Config validation (URL — https, or http with `tls_skip_verify` — `timeout`, `max_body_size`, `auto_auth_path`, `default_role`, the `user_auth_path`/`user_auth_role` pairing, `tls_skip_verify`/`ca_data`)
- Optional per-request dispatch for multi-protocol providers (different upstream, credentials, header policy, or body cap per request)
- Opt-in hooks for refusing requests, rewriting responses, MCP policy enforcement, and answering Warden's own failures in the upstream's error shape

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
    ParseStreamBody:    true,
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
- user_auth_path: Auth mount for the user principal (optional)
- user_auth_role: Role for the user principal (optional)
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

and add `Spec` to the map in `registered_specs_test.go`, which counts the shipped specs and runs `ValidateSpec` on each.

That's it. Your provider supports:
- `warden provider enable myprovider`
- `warden write myprovider/config myprovider_url=... auto_auth_path=auth/jwt/`
- `POST /myprovider/gateway/v1/some/endpoint` (role provided via `X-Warden-Role` header)
- `POST /myprovider/role/{role}/gateway/v1/some/endpoint` (role embedded in URL path)

Both paths perform implicit authentication and credential injection. The only difference is how the role is communicated: via the `X-Warden-Role` header or embedded in the URL path.

## ProviderSpec reference

### Required fields

`ValidateSpec` enforces `Name`, `URLConfigKey` and `ExtractCredentials`; a spec missing one yields a factory that fails at mount time. The others are required in practice.

| Field | Description |
|-------|-------------|
| `Name` | Provider identifier (e.g., `"datadog"`). Used for backend type, logging, and help text. |
| `DefaultURL` | Upstream API base URL (e.g., `"https://api.datadoghq.com"`). Leave `""` when the upstream is per-deployment (GitLab, Kubernetes, MCP): requests are refused until the mount configures one. |
| `URLConfigKey` | Config key for the upstream URL (e.g., `"datadog_url"`). Appears in config read/write. |
| `DefaultTimeout` | Default request timeout. Use `120 * time.Second` for AI inference, `30 * time.Second` for REST APIs. Zero means no deadline at all — always set it. |
| `HelpText` | Backend help description shown in `warden path-help`. |
| `ExtractCredentials` | Function that extracts credentials from the request and returns headers to inject. See [Credential extractors](#credential-extractors). |

### Optional fields

| Field | Default | Description |
|-------|---------|-------------|
| `ParseStreamBody` | `false` | Let core parse the request body (any JSON media type, or a form) so policies can match on its fields, e.g. `model` or `max_tokens`. Every shipped provider except `mcp` sets `true`. Specs that set `ShouldEnforceMCPPolicy` MUST leave it `false`. A provider carrying a non-JSON protocol on the side sets `true` and suppresses parsing per request via `Dispatch.BypassBodyParsing`. |
| `UserAgent` | `"warden-{Name}-proxy"` | User-Agent header on proxied requests, when the client sent none. |
| `ExtractToken` | `DefaultTokenExtractor` | Override how the agent (and, on a mount with `user_auth_path`, the user) principal is read from the request. See [Custom token extraction](#custom-token-extraction). |
| `ExtraHeadersToRemove` | `[]` | Provider-specific headers to strip beyond the [base set](#base-headers-removed). |
| `DefaultHeaders` | `nil` | Static headers always set on proxied requests, overriding the client's value (e.g., `{"Content-Type": "application/vnd.api+json"}` for TFE). |
| `DynamicHeaders` | `nil` | Function returning headers derived from config state, called on every request. They are fallbacks: set only when the client did not send that header. Per-request dispatches can opt out via `Dispatch.SkipDynamicHeaders`. |
| `DefaultAccept` | `"application/json"` | Override the Accept header injected when the client sent none. Per-request overrides are available via `Dispatch.Accept` and `Dispatch.SkipDefaultAccept`. |
| `ExtraConfigFields` | `nil` | Additional config fields beyond the [standard nine](#extra-config-fields). |
| `OnConfigRead` | `nil` | Add extra fields to config read response from provider state. |
| `OnConfigWrite` | `nil` | Process extra config fields during config write. Gets a clone of the state; return an error to reject the write. |
| `OnInitialize` | `nil` | Load extra fields from persisted config during initialization. |
| `OnFirstConfig` | `nil` | Stamp create-time defaults into state, once per mount. See [Create-time defaults](#create-time-defaults). |
| `ValidateExtraConfig` | `nil` | Custom validation for provider-specific fields in mount-time config. Config writes are validated in `OnConfigWrite`. See [Validating config](#validating-config). |
| `NewTransport` | `DefaultNewTransport` | Factory returning `(*http.Transport, func())`. Called lazily on first instantiation. Override for custom transport settings. |
| `ResolveUpstream` | `nil` | Per-request override hook for upstream URL, credential extractor, Accept header, dynamic headers, body cap, and body parsing. May run several times per request, so it must be cheap and side-effect free. See [Per-request dispatch](#per-request-dispatch). |
| `RefuseRequest` | `nil` | Refuse a request the provider will not forward, before any credential is extracted. See [Refusing requests](#refusing-requests). |
| `RewriteResponse` | `nil` | Decide per request whether the upstream response is rewritten. See [Rewriting responses](#rewriting-responses). |
| `ModifyResponse` | `nil` | Rewrite the upstream response. Both this and `RewriteResponse` must be set. See [Rewriting responses](#rewriting-responses). |
| `GetAuthRoleFromRequest` | `nil` | Optional hook to derive the auth role from the HTTP request (e.g., Basic Auth username for Git smart-HTTP). Consulted after URL-path role lookup; `X-Warden-Role` header always wins. See [Custom role extraction](#custom-role-extraction). |
| `IsUnauthenticatedRequest` | `nil` | Optional hook to declare that a specific request should bypass authentication and pass through to the upstream. Used by protocols that probe for auth (e.g., Git smart-HTTP first probe → upstream `WWW-Authenticate` → client retry with Basic Auth). The static `UnauthenticatedPaths` list still applies as a fallback when the hook is unset or returns `false`. The handler runs with `req.Credential == nil` for unauthenticated requests — see the `StreamUnauthenticated` guard in `gateway.go`. |
| `ShouldEnforceMCPPolicy` | `nil` | Opt into body-authoritative MCP policy enforcement. Requires `ParseStreamBody: false`. See [MCP providers](#mcp-providers). |
| `SelectTimeout` | `nil` | Pick a per-request deadline in place of the mount timeout; `0` keeps the mount timeout. See [MCP providers](#mcp-providers). |
| `RenderGatewayError` | `nil` | Optional hook to answer a gateway request Warden failed itself in the upstream's native error shape, so the provider's SDKs can parse it: authentication, policy and credential issuance, the gateway's own failures (credential not usable, upstream address, `RefuseRequest`), and the proxy's 502/504. Must keep `f.Status` as the status. Build the message with `WardenErrorMessage` so it reads as Warden's, not the upstream's. Return `nil`, or leave the hook unset, to keep Warden's generic `{"errors": [...]}` body. Errors the upstream sends are never passed to it. On an MCP mount the request carries the call id; see `WithMCPCallID`. |

## Credential extractors

Built-in extractors cover common auth patterns:

### `BearerAPIKeyExtractor`

Extracts `api_key` from a `TypeAPIKey` credential, injects as `Authorization: Bearer {key}`.

```go
ExtractCredentials: httpproxy.BearerAPIKeyExtractor,
```

Used by: Ansible Tower, Cohere, Grafana, Mistral, PagerDuty, Sentry, ServiceNow, Slack, Splunk, TFE.

### `HeaderAPIKeyExtractor(headerName)`

Extracts `api_key` from a `TypeAPIKey` credential, injects into a custom header.

```go
ExtractCredentials: httpproxy.HeaderAPIKeyExtractor("Api-Key"),
```

Used by: New Relic.

### `MultiFieldAPIKeyExtractor(requiredFields, optionalFields)`

Extracts multiple fields from a `TypeAPIKey` credential and maps them to headers. Required fields must be present; optional fields are included when non-empty.

```go
ExtractCredentials: httpproxy.MultiFieldAPIKeyExtractor(
    map[string]string{"api_key": "DD-API-KEY"},                 // required
    map[string]string{"application_key": "DD-APPLICATION-KEY"}, // optional
),
ExtraHeadersToRemove: []string{"DD-APPLICATION-KEY"},
```

Used by: Datadog. An optional header is injected only when the credential carries the field, so it must also be in `ExtraHeadersToRemove`: otherwise a client's own value reaches the upstream beside Warden's credential.

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

Used by: GitHub, GitLab, Kubernetes.

### Custom extractor

For providers whose header shape depends on the credential type, or that need special logic. Dynatrace takes a static API token as `Api-Token` and an OAuth token as `Bearer`:

```go
func dynatraceCredentialExtractor(req *logical.Request) (map[string]string, error) {
    if req.Credential == nil {
        return nil, fmt.Errorf("no credential available")
    }
    switch req.Credential.Type {
    case credential.TypeAPIKey:
        apiKey := req.Credential.Data["api_key"]
        if apiKey == "" {
            return nil, fmt.Errorf("credential missing api_key field")
        }
        return map[string]string{"Authorization": "Api-Token " + apiKey}, nil
    case credential.TypeOAuthBearerToken:
        token := req.Credential.Data["api_key"]
        if token == "" {
            return nil, fmt.Errorf("credential missing api_key field")
        }
        return map[string]string{"Authorization": "Bearer " + token}, nil
    default:
        return nil, fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
    }
}
```

`req.HTTPRequest` is available when injection depends on the request (see Anthropic's `newExtractor`). The same `ExtraHeadersToRemove` rule applies: any header injected on only some branches must be stripped, or a client's own value rides through.

## Custom token extraction

`ExtractToken` resolves the two principals a request can carry: the agent and, on a mount with `user_auth_path`, the user (`userLeg` is true there).

```go
type TokenExtractorFunc func(r *http.Request, userLeg bool) (agent, user string)
```

The default, `DefaultTokenExtractor`, is `logical.ExtractTokensDefault`:

1. `X-Warden-Token` present → agent = it, never a user.
2. `userLeg` and `X-Warden-Agent-Token` present → agent = it, user = `Authorization: Bearer`.
3. `userLeg` and a trusted client certificate → agent = the certificate, user = `Authorization: Bearer`.
4. Otherwise → agent = `Authorization: Bearer`, no user.

Override it when your provider's SDK sends its credential on a native header. The contract: when `userLeg` is false, return `user == ""` and resolve the agent exactly as before the user leg existed. `X-Warden-Token` never opens the user leg; a native channel (`x-api-key`, `Api-Key`, `PRIVATE-TOKEN`) does. `logical.ExtractTokensWithChannels` applies that rule to a list of headers tried in order:

```go
// Anthropic clients send the agent's token on x-api-key, leaving Authorization
// to the user.
func extractTokens(r *http.Request, userLeg bool) (agent, user string) {
    return logical.ExtractTokensWithChannels(r, userLeg, "X-Warden-Token", "x-api-key")
}

var Spec = &httpproxy.ProviderSpec{
    // ...
    ExtractToken:         extractTokens,
    ExtraHeadersToRemove: []string{"x-api-key"}, // the inbound agent channel must not reach the upstream
}
```

For a scheme carried inside `Authorization` (`ApiKey `, `Splunk `), build on `logical.StripScheme`, `logical.AgentOutOfBand` and `logical.StripBearer` — see `provider/elastic/provider.go`. For Basic Auth, see `provider/github/provider.go`.

## Extra config fields

Every mount has nine standard config fields: the URL (`URLConfigKey`), `max_body_size`, `timeout`, `auto_auth_path`, `default_role`, `user_auth_path`, `user_auth_role`, `tls_skip_verify` and `ca_data`. For anything beyond them, use `ExtraConfigFields` with the state callbacks. See the GitHub provider for a complete example:

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

**State rules.** `OnConfigWrite` and `OnFirstConfig` receive a clone of the state and may mutate it. Every hook that runs on the request path — `DynamicHeaders`, `ResolveUpstream`, `RefuseRequest`, `RewriteResponse`, `SelectTimeout` — receives the live map and must only read it: writers replace the reference under a lock, so an in-place mutation would race. Numbers round-trip through storage as `float64` or `json.Number`; read them back with `ReadInt64Config`.

### Create-time defaults

`OnFirstConfig` runs once in a mount's life: when initialization finds no persisted config, just before the defaults are persisted. Use it for a setting that new mounts get on by default while mounts created before the setting existed — whose persisted config lacks the key — keep the old behaviour. It must leave keys already set from mount-time config alone:

```go
OnFirstConfig: func(state map[string]any) map[string]any {
    if _, set := state[parseRequestBodyKey]; !set {
        state[parseRequestBodyKey] = true
    }
    return state
},
```

The value is persisted through `OnConfigRead`, so the key must also be returned there.

## Per-request dispatch

A provider that serves a single protocol on a single upstream URL needs nothing here. A provider that carries **multiple protocols on the same mount** — e.g., GitHub's REST API and Git smart-HTTP, both rooted at `/github/gateway/...` — can route a subset of paths to a different upstream, with different credential formatting, header policy, and body cap, via `ResolveUpstream`.

`ResolveUpstream` is consulted up to three times per request — by `ShouldParseStreamBody` and `StreamBodyLimit` (so core's parse buffer matches the gateway's cap) and by the gateway itself — each time against a read-lock snapshot of the backend state, before credentials are extracted. It must therefore be cheap, deterministic for a given request and state, and free of side effects. The hook returns a `Dispatch` (the per-request override carrier) and a boolean. When the boolean is `false` — or when the hook is unset — the spec/mount defaults apply unchanged.

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

**Example: Git smart-HTTP.** Providers that proxy both a REST API and Git smart-HTTP (clone/fetch/push) on the same mount route per-request: REST paths fall through to the spec defaults, Git paths get a `Dispatch` that points at the Git host with HTTP Basic Auth, raises the body cap for pushes, suppresses Accept/dynamic-header injection (Git negotiates its own content types), and bypasses body parsing (pack-files are binary). The `provider/sdk/githttp` SDK factors this out — providers call `githttp.BuildHooks(Options{...})` and wire the returned `ResolveUpstream` onto their spec:

```go
var gitHooks = githttp.BuildHooks(githttp.Options{
    BasicAuthUsername: "x-access-token",                  // host-specific (GitLab uses "oauth2")
    CredentialType:    credential.TypeGitHubToken,        // host-specific
    TokenField:        "token",                           // host-specific
    DeriveGitURL:      deriveGitURL,                      // host-specific (api.github.com → github.com)
})

var Spec = &httpproxy.ProviderSpec{
    // ...
    ResolveUpstream: gitHooks.ResolveUpstream,
}
```

`BypassBodyParsing` is honoured by the framework's request-aware body-parsing decision, which consults `ResolveUpstream` on every request before deciding whether to parse — so spec authors set `ParseStreamBody: true` on the spec and selectively suppress parsing per request via `Dispatch`.

See `provider/sdk/githttp` for the SDK and `provider/github/git.go` for a consumer's host-specific wiring.

**State-driven dispatch.** The hook may ignore the request and always return `true`, to pick the credential extractor from mount config rather than from the path. The `rest` provider builds its extractor from the configured token header, prefix and static headers, and decides body parsing from `parse_request_body`; `prometheus` chooses bearer or basic auth. `Spec.ExtractCredentials` then only covers a mount whose state has no choice yet.

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

**Example: role from a custom header.** A provider that wants to honour a non-Warden client convention (e.g., a partner system that already sends `X-Tenant-Role`) writes a hook that reads the header and returns its value, or `""` to fall through:

```go
func roleFromTenantHeader(r *http.Request) string {
    return r.Header.Get("X-Tenant-Role") // "" falls through to default_role
}

var Spec = &httpproxy.ProviderSpec{
    // ...
    GetAuthRoleFromRequest: roleFromTenantHeader,
}
```

The hook can also discriminate on path shape — e.g., only return a role on paths that match the alternate protocol, and `""` on REST paths so REST callers keep their default behaviour. The `provider/sdk/githttp` SDK does exactly that for Git smart-HTTP (Basic Auth username on `.git/...` paths; `""` elsewhere) — wire it via:

```go
var Spec = &httpproxy.ProviderSpec{
    // ...
    GetAuthRoleFromRequest: gitHooks.GetAuthRoleFromRequest,
}
```

See `provider/sdk/githttp` for the SDK and `provider/github/git.go` for a consumer's host-specific wiring.

## Validating config

The framework validates the standard fields on mount and on every config write: the URL must be `https://` with a host (`http://` is accepted when `tls_skip_verify` is true), `max_body_size` must be within 1 byte–100MB, `timeout` at least 1s, and `user_auth_role` requires `user_auth_path`.

Provider-specific checks go in two places:

- `ValidateExtraConfig(conf)` runs against the **mount-time** config only.
- On a **config write**, return an error from `OnConfigWrite`: the write is answered 400 and nothing is applied.

A check that must hold on both paths is written once and called from both — see `checkURL` in `provider/msgraph/provider.go`.

```go
var Spec = &httpproxy.ProviderSpec{
    // ...
    ValidateExtraConfig: func(conf map[string]any) error {
        addr, ok := conf["gitlab_address"].(string)
        if !ok || addr == "" {
            return fmt.Errorf("gitlab_address is required")
        }
        return nil
    },
}
```

## Refusing requests

`RefuseRequest` lets a provider refuse a request it will not forward — an operation it does not support, or an upstream it no longer trusts:

```go
RefuseRequest func(r *http.Request, providerURL string, state map[string]any) (int, error)
```

A `nil` error lets the request through. It runs in the gateway after authentication, policy and credential issuance, with `providerURL` already resolved by `ResolveUpstream`, and before any credential is extracted — so nothing reaches the upstream for a refused request. It only ever narrows what policy allowed. A status outside 400–599 is answered as 400. The error is rendered through `RenderGatewayError` when the spec sets it, otherwise written as plain text, so its message is client-facing. The state rules of `ResolveUpstream` apply.

```go
RefuseRequest: func(r *http.Request, _ string, _ map[string]any) (int, error) {
    if api, ok := httpproxy.PathAfterGateway(r.URL.Path); ok && strings.HasSuffix(api, "/$batch") {
        return http.StatusBadRequest, errBatchNotSupported
    }
    return 0, nil
},
```

## Rewriting responses

A provider whose upstream returns absolute URLs — Graph's paging links, say — can rewrite them back onto the gateway:

```go
RewriteResponse func(r *http.Request, state map[string]any) bool
ModifyResponse  func(resp *http.Response, rc RewriteContext) error

type RewriteContext struct {
    Prefix      string // this mount's gateway URL as the client addressed it, through "/gateway"
    MaxBodySize int64  // how much of a response the hook may buffer
}
```

- Both hooks must be set for either to take effect; a provider that sets neither pays nothing.
- `RewriteResponse` decides per request. It sees the **outbound** request — URL already pointed at the upstream, headers already prepared — and the state rules of `ResolveUpstream` apply.
- When it returns true and Warden knows its external base URL, `Accept-Encoding` is dropped so the body arrives uncompressed, and the response is handed to `ModifyResponse`. Without an external base URL the response streams through untouched.
- `ModifyResponse` runs concurrently on the proxy's response path, so it must be safe for concurrent use, and should fail open: a body it cannot rewrite is better passed through than refused. An error it returns is answered as a 502.
- A hook that replaces the body must also fix `ContentLength`, `Content-Length` and `Transfer-Encoding` — see `provider/msgraph/links.go`.
- On a response the policy layer prunes with an MCP list filter, the filter runs instead of `ModifyResponse`.

## MCP providers

An MCP provider fronts a JSON-RPC server, and policy is judged on the method and tool the body asks for. The `mcp` provider is the reference:

```go
var Spec = &httpproxy.ProviderSpec{
    Name:               "mcp",
    URLConfigKey:       "mcp_url",
    DefaultTimeout:     DefaultMCPTimeout,
    ParseStreamBody:    false, // required with ShouldEnforceMCPPolicy
    ExtractCredentials: extractBearerToken,
    // DefaultAccept unset: MCP clients negotiate their own.

    ShouldEnforceMCPPolicy: func(req *logical.Request) bool {
        return req != nil && req.HTTPRequest != nil && req.HTTPRequest.Method == http.MethodPost
    },
    RenderGatewayError: httpproxy.RenderMCPGatewayError,
    SelectTimeout:      httpproxy.SelectListenTimeout,
    ExtraConfigFields: map[string]*framework.FieldSchema{
        httpproxy.ListenTimeoutKey: httpproxy.ListenTimeoutField(),
    },
    // OnConfigRead/OnConfigWrite/OnInitialize: ReadListenTimeout,
    // WriteListenTimeout, InitializeListenTimeout.
}
```

- **`ShouldEnforceMCPPolicy`** — when it returns true, core buffers the body (up to the mount's `max_body_size`) and strict-parses it as JSON-RPC before policy runs. It fails closed: a body that is not JSON-RPC is refused as malformed, so gate on the method (POST), not on `Content-Type`, and leave SSE GETs and session-close DELETEs alone. The stream-body parser would consume the body first, hence `ParseStreamBody: false`. Every response on such a mount is marked `Cache-Control: private`.
- **List pruning** — when policy attaches a list filter, `tools/list` and the other list responses are pruned to the items the caller may use, with no spec involvement. A body that cannot be parsed fails closed with a 502.
- **`SelectTimeout`** — `SelectListenTimeout` gives `subscriptions/listen` streams the mount's `listen_timeout` and keeps every other call on the mount timeout. Return `0` to keep the mount timeout.
- **`RenderMCPGatewayError`** — answers Warden's refusals as JSON-RPC errors for the call, echoing its id (carried by `WithMCPCallID`), so the client keeps its session.

## Base headers removed

Every proxied request has these headers stripped before credential injection:

**Security:** `Authorization`, `X-Warden-Token`, `X-Warden-Agent-Token`, `X-Warden-User-Token` (retired; still stripped so a stale client cannot leak it), `X-Warden-Role`, `X-Warden-Provider`, `X-Warden-Subject-Token`, `X-Warden-Actor-Token`

**Hop-by-hop:** `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `Te`, `Trailers`, `Transfer-Encoding`, `Upgrade`, plus every header the client named in its `Connection` header

**Proxy:** `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Real-Ip`, `Forwarded`

Add provider-specific headers via `ExtraHeadersToRemove`: a native inbound agent channel (e.g., `x-api-key` for Anthropic) and any header the extractor injects on only some branches.

## When NOT to use httpproxy

This framework is for standard HTTP reverse proxy providers. Do **not** use it for:

- **AWS, Alibaba Cloud, mcp_aws** -- require request signing (SigV4 and similar), not simple header injection. `mcp_aws` still reuses this package's config, transport and MCP helpers.
- **Azure, GCP** -- embed the target host in the URL path (`/gateway/{host}/{path}`)
- **Vault** -- has unauthenticated paths and a different credential lifecycle
- **RDS, Redshift** -- database access, built on `provider/sdk/dbaccess`

These providers have fundamentally different request handling and should remain as custom implementations. A provider serving a REST API and an S3-compatible API on one mount (Cloudflare, IBM Cloud, OVH, Scaleway) uses [`provider/sdk/dualgateway`](../dualgateway/README.md).

## Existing providers using httpproxy

The shipped specs are listed, and checked with `ValidateSpec`, in `registered_specs_test.go`. To see a hook in use, read:

| Pattern | Providers |
|---------|-----------|
| Built-in extractors | `slack`, `newrelic`, `datadog`, `github` |
| Custom extractor | `dynatrace` (by credential type), `atlassian` (by credential fields) |
| Custom `ExtractToken` | `anthropic` (native header), `elastic` (scheme in `Authorization`), `github` (Basic Auth) |
| Extra config + `DynamicHeaders` | `github`, `grafana` |
| State-driven dispatch | `rest`, `prometheus` |
| Multi-protocol dispatch (via `githttp`) | `github`, `gitlab` |
| `OnFirstConfig` | `rest` |
| `RefuseRequest`, response rewriting | `msgraph` |
| MCP hooks | `mcp` |
| `RenderGatewayError` | `openai`, `anthropic`, `msgraph`, `mcp` |
