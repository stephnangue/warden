# dualgateway - Dual-Mode Gateway Provider Framework

The `dualgateway` package provides a configuration-driven framework for building Warden gateway providers that expose **both** a REST API and an S3-compatible Object Storage surface behind a single mount. The framework auto-detects the request type per request: standard requests get a credential header injected and forwarded, while AWS SigV4 requests are verified, re-signed with real provider credentials, and forwarded to a regional S3 endpoint. Instead of writing ~600 lines of transport, signing, and config plumbing per provider, you declare a `ProviderSpec` and get a fully functional backend in 25–80 lines.

This sits alongside [provider/sdk/httpproxy](../httpproxy/README.md) (single-protocol REST proxies) and [provider/sdk/dbaccess](../dbaccess/README.md) (database credential vending).

## What you get for free

- Streaming gateway paths (`gateway`, `gateway/.*`, `role/[^/]+/gateway`, `role/[^/]+/gateway/.*`) with auto-detection of REST API vs S3 per request
- SigV4 lifecycle for S3 mode: incoming signature verification, re-sign with real provider credentials, forward to the regional endpoint
- API-mode credential injection via configurable header (`Authorization: Bearer …`, `X-Auth-Token: …`, etc.)
- Config CRUD endpoint (`config`) with storage persistence, TLS settings (`tls_skip_verify`, `ca_data`), timeout and max-body-size enforcement
- Transparent auth: token extraction from `X-Warden-Token`, `Authorization: Bearer`, or the SigV4 `access_key_id` (JWT or role name)
- Shared HTTP/2 transport with TLS 1.2+, session caching, and connection pooling — initialized lazily and shared across all backends in the process
- Spec validation at mount time (catches missing required fields before any request hits)

## Quick start: a Scaleway-shaped provider

Create a single file at `provider/<name>/provider.go`:

```go
package myprovider

import (
    "fmt"
    "time"

    "github.com/stephnangue/warden/credential"
    "github.com/stephnangue/warden/provider/sdk/dualgateway"
)

var Spec = &dualgateway.ProviderSpec{
    Name:           "myprovider",
    HelpText:       helpText,
    CredentialType: credential.TypeMyProviderKeys,

    DefaultURL:     "https://api.myprovider.com",
    URLConfigKey:   "myprovider_url",
    DefaultTimeout: 30 * time.Second,
    UserAgent:      "warden-myprovider-proxy",

    APIAuth: dualgateway.APIAuthStrategy{
        HeaderName:        "X-Auth-Token",
        HeaderValueFormat: "%s",
        CredentialField:   "secret_key",
    },

    S3Endpoint: func(_ map[string]any, region string) string {
        return fmt.Sprintf("s3.%s.myprovider.cloud", region)
    },
}

var Factory = dualgateway.NewFactory(Spec)

const helpText = `
The myprovider provider proxies requests to the MyProvider API and S3-compatible
Object Storage. The request type is auto-detected from the Authorization header.

Configuration:
- myprovider_url:  API base URL (default: https://api.myprovider.com)
- max_body_size:   Maximum request body size (default: 10MB, max: 100MB)
- timeout:         Request timeout (default: 30s)
- auto_auth_path:  Auth mount for implicit authentication (e.g., 'auth/jwt/')
- default_role:    Fallback role when not specified in URL path or header
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
- `warden write myprovider/config myprovider_url=https://api.myprovider.com auto_auth_path=auth/jwt/`
- API mode: `POST /v1/myprovider/gateway/some/api/path` (header injected, request forwarded)
- API mode with role: `POST /v1/myprovider/role/{role}/gateway/some/api/path`
- S3 mode: any AWS SDK pointed at `https://<warden>/v1/myprovider/gateway/` with the provider's region — Warden verifies the SigV4 signature, re-signs with real provider keys, and forwards to `s3.{region}.myprovider.cloud`

## ProviderSpec reference

### Required fields

Enforced by `validateSpec` at factory construction — missing any of these makes the backend fail to mount.

| Field | Description |
|-------|-------------|
| `Name` | Provider identifier (e.g., `"scaleway"`, `"ovh"`). Used for backend type, log subsystem, and shutdown hook key. |
| `DefaultURL` | Upstream REST API base URL (e.g., `"https://api.scaleway.com"`). |
| `URLConfigKey` | Config key the operator uses to override the URL (e.g., `"scaleway_url"`). |
| `S3Endpoint` | Function returning the S3 hostname for a given region and backend state. See [The S3Endpoint callback](#the-s3endpoint-callback). |
| `APIAuth.HeaderName` | Header to set on API-mode requests (e.g., `"Authorization"`, `"X-Auth-Token"`). |
| `APIAuth.HeaderValueFormat` | `fmt`-style format string applied to the credential value (`"%s"` for raw, `"Bearer %s"` for Bearer). |
| `APIAuth.CredentialField` | Name of the field on `credential.Data` to extract (e.g., `"api_token"`, `"secret_key"`). |

### Strongly recommended

Not enforced by validation, but every default code path reads them — leaving them blank silently breaks something.

| Field | Why |
|-------|-----|
| `HelpText` | Shown by `warden path-help`. Document both API and S3 paths and the supported S3 regions. |
| `CredentialType` | Default `ExtractAPICredential` and `ExtractS3Credentials` reject any credential whose `Type` does not match. Leave empty only when you supply both extractor overrides. |
| `DefaultTimeout` | Used when `config.timeout` is unset. `0` makes every request fail with a deadline-exceeded error. |
| `UserAgent` | Sent on every proxied request. Convention: `"warden-<name>-proxy"`. |
| `APIAuth.StripAuthorization` | `true` if the provider's auth uses `Authorization: Bearer …` (so the incoming Warden Authorization header must be removed); `false` if the provider uses a separate header (e.g., `X-Auth-Token`) and the incoming Authorization header is harmless. See [APIAuthStrategy patterns](#apiauthstrategy-patterns). |

### Optional extensibility hooks

| Field | Purpose | Used by |
|-------|---------|---------|
| `ExtraConfigKeys` | Additional allowed config keys beyond the standard set (`url`, `max_body_size`, `timeout`, `auto_auth_path`, `default_role`, `tls_skip_verify`, `ca_data`). | Cloudflare, IBM Cloud |
| `ExtraConfigFields` | `framework.FieldSchema` map keyed by name. If `nil`, extra keys are treated as `TypeString`. | Cloudflare, IBM Cloud |
| `OnConfigParsed` | Runs after standard config parsing; returns a state map stored on the backend and passed to `S3Endpoint` / `RewriteAPITarget`. | Cloudflare, IBM Cloud |
| `ExtractAPICredential` | Override the default API credential extractor. The default reads `APIAuth.CredentialField` from `credential.Data` after validating `CredentialType`. | (none currently) |
| `ExtractS3Credentials` | Override the default S3 credential extractor. The default reads `access_key` / `secret_key`. R2 and COS use `access_key_id` / `secret_access_key`, so they override. | Cloudflare, IBM Cloud |
| `RewriteAPITarget` | Override API-mode target URL construction (default: `providerURL + apiPath`). For providers that route to multiple upstream hostnames based on path. S3 requests bypass this hook entirely. | IBM Cloud |

## APIAuthStrategy patterns

There are two real-world recipes, and the choice hinges on whether the provider's own auth uses the standard `Authorization` header or a custom one.

**Bearer-style** — provider uses `Authorization: Bearer <token>`. Strip the incoming Warden Authorization header so the injected one is the only `Authorization` upstream sees:

```go
APIAuth: dualgateway.APIAuthStrategy{
    HeaderName:         "Authorization",
    HeaderValueFormat:  "Bearer %s",
    CredentialField:    "api_token",
    StripAuthorization: true,
},
```

Used by OVH, Cloudflare, IBM Cloud.

**Custom-header-style** — provider uses a separate header (e.g., `X-Auth-Token`). The incoming Warden Authorization header is not in the way and can be left alone:

```go
APIAuth: dualgateway.APIAuthStrategy{
    HeaderName:        "X-Auth-Token",
    HeaderValueFormat: "%s",
    CredentialField:   "secret_key",
    // StripAuthorization defaults to false
},
```

Used by Scaleway.

## The S3Endpoint callback

```go
S3Endpoint func(state map[string]any, region string) string
```

Returns the S3 target **hostname only** (no scheme, no path). The `region` argument comes from parsing the SigV4 `Authorization` header. The `state` argument is whatever `OnConfigParsed` returned, or `nil`.

Three real callbacks:

```go
// Scaleway: region-per-host, no extra config
S3Endpoint: func(_ map[string]any, region string) string {
    return fmt.Sprintf("s3.%s.scw.cloud", region)
},

// OVH: same shape, different domain
S3Endpoint: func(_ map[string]any, region string) string {
    return fmt.Sprintf("s3.%s.io.cloud.ovh.net", region)
},

// Cloudflare R2: account-scoped, optional jurisdiction subdomain
S3Endpoint: func(state map[string]any, region string) string {
    accountID, _    := state["account_id"].(string)
    jurisdiction, _ := state["r2_jurisdiction"].(string)
    if jurisdiction != "" {
        return fmt.Sprintf("%s.%s.r2.cloudflarestorage.com", accountID, jurisdiction)
    }
    return fmt.Sprintf("%s.r2.cloudflarestorage.com", accountID)
},
```

## RewriteAPITarget: multi-host API routing

For the rare case where the API surface spans multiple upstream hostnames and the request path encodes which one to hit. IBM Cloud is the canonical example: each service (IAM, COS control plane, etc.) lives on a different host.

```go
RewriteAPITarget: func(providerURL, apiPath string, state map[string]any) (string, error) {
    host, rest, err := splitHostFromPath(apiPath) // e.g., "/iam.cloud.ibm.com/identity/token"
    if err != nil {
        return "", err
    }
    suffixes, _ := state["allowed_host_suffixes"].([]string)
    if !hostAllowed(host, suffixes) {
        return "", fmt.Errorf("host %q not in allowed_host_suffixes", host)
    }
    return "https://" + host + rest, nil
},
```

Two things to keep in mind:

- **Validate the host.** Without an allowlist this becomes an open proxy. IBM Cloud defaults to `.cloud.ibm.com,.appdomain.cloud` and lets the operator override via config.
- **S3 requests bypass this hook** — they always go through `S3Endpoint`. If you need per-region S3 hostnames in addition to multi-host API routing, you do both.

## Transparent auth and token extraction

The framework's token extractor walks three sources in order, supporting all three of Warden's transparent auth modes without provider involvement:

1. **`X-Warden-Token` header** — explicit Warden token.
2. **`Authorization: Bearer <token>`** — explicit Warden token via the standard header.
3. **SigV4 `access_key_id`** — for S3 clients that cannot send a separate header. Two sub-modes are recognized:
    - Value starts with `eyJ` → treated as a JWT (transparent auth via `auto_auth_path`); the role is taken from the URL path or `X-Warden-Role`.
    - Otherwise → treated as a role name (cert-style transparent auth); the same value populates the SigV4 secret slot, since the client doesn't know real keys.

This is the part that makes dualgateway different from `httpproxy`: an S3 SDK can speak SigV4 without any Warden-specific glue, because Warden hides itself in the access-key field.

## When NOT to use dualgateway

- **Single-protocol REST APIs.** No S3 surface? Use [httpproxy](../httpproxy/README.md) — `dualgateway` carries SigV4 plumbing you don't need.
- **Database credential vending.** Workload connects directly to the DB? Use [dbaccess](../dbaccess/README.md) — `dualgateway` proxies traffic, which is the wrong shape.
- **Pure SigV4 with no API surface.** If the provider is *only* an S3-compatible store, you can build directly on `framework.StreamingBackend` + [provider/sdk/sigv4](../sigv4) without inheriting the API-mode machinery. Look at AWS for prior art.

## Existing providers using dualgateway

| Provider | API auth | S3 hostname template | Hooks used |
|----------|----------|----------------------|------------|
| [Scaleway](../../scaleway/provider.go) | `X-Auth-Token: <secret_key>` | `s3.<region>.scw.cloud` | none |
| [OVH](../../ovh/provider.go) | `Authorization: Bearer <api_token>` (strips incoming) | `s3.<region>.io.cloud.ovh.net` | none |
| [Cloudflare](../../cloudflare/provider.go) | `Authorization: Bearer <api_token>` (strips) | `<account>[.<jurisdiction>].r2.cloudflarestorage.com` | `ExtraConfig*`, `OnConfigParsed`, `ExtractS3Credentials` |
| [IBM Cloud](../../ibmcloud/provider.go) | `Authorization: Bearer <access_token>` (strips) | `s3[.private\|.direct].<region>.cloud-object-storage.appdomain.cloud` | `ExtraConfig*`, `OnConfigParsed`, `RewriteAPITarget`, `ExtractS3Credentials` |
