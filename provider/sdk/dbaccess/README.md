# dbaccess - Database Access Provider Framework

The `dbaccess` package provides a configuration-driven framework for building Warden access backends — providers that vend short-lived database connection strings via a `grants/{name}` + `access/{name}` path pattern. Instead of writing ~230 lines of CRUD boilerplate per provider, you declare a `ProviderSpec` and a `FormatAccess` callback and get a fully functional backend in 65–85 lines.

This mirrors the shape of [provider/sdk/httpproxy](../httpproxy/README.md) for streaming providers.

## What you get for free

- Grant CRUD endpoints (`grants/{name}` read / update / delete) with storage persistence
- Access endpoint (`access/{name}` read) that mints the grant's credential and hands it to your `FormatAccess`
- Config endpoint inherited from `framework.AccessBackend` — including `auto_auth_path` for implicit / transparent authentication
- Framework-managed grant fields: `credential_spec` (required at write time) and `description` are added automatically, so you only declare the database-specific fields
- JSON storage layout that is backward-compatible with the pre-refactor typed-struct grants

## Quick start: a Redshift-shaped provider

Create a single file at `provider/<name>/provider.go`:

```go
package myprovider

import (
    "fmt"

    "github.com/stephnangue/warden/credential"
    "github.com/stephnangue/warden/framework"
    "github.com/stephnangue/warden/provider/sdk/dbaccess"
)

var Spec = &dbaccess.ProviderSpec{
    Name: "myprovider",
    GrantFields: map[string]*framework.FieldSchema{
        "db_name": {
            Type:        framework.TypeString,
            Description: "Database name to include in the connection string",
        },
    },
    FormatAccess: formatAccess,
    HelpText:     helpText,
}

var Factory = dbaccess.NewFactory(Spec)

func formatAccess(cred *credential.Credential, grant dbaccess.Grant, principal string) map[string]interface{} {
    return map[string]interface{}{
        "connection_string": fmt.Sprintf(
            "host=%s port=%s dbname=%s user=%s password='%s' sslmode=require application_name=%s",
            cred.Data["db_host"],
            cred.Data["db_port"],
            grant["db_name"],
            cred.Data["db_user"],
            cred.Data["auth_token"],
            principal,
        ),
        "lease_duration": int(cred.LeaseTTL.Seconds()),
    }
}

const helpText = `
The myprovider provider vends short-lived database connection strings backed
by IAM authentication. Workloads call /myprovider/access/<grant-name> to
receive a ready-to-use DSN; Warden does not proxy database traffic.

Configuration:
- auto_auth_path: Auth mount path for implicit authentication (e.g. 'auth/jwt/')

Grants (path: myprovider/grants/<name>):
- credential_spec: Credential spec name to mint for this grant (required)
- db_name:         Database name to include in the connection string
- description:     Human-readable description
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
- `warden write myprovider/config auto_auth_path=auth/jwt/`
- `warden write myprovider/grants/analytics credential_spec=prod-readonly db_name=analytics`
- `warden read myprovider/access/analytics` — returns the formatted connection string

## ProviderSpec reference

| Field | Required | Description |
|-------|----------|-------------|
| `Name` | yes | Provider identifier (e.g. `"rds"`, `"redshift"`). Used as the backend type, log subsystem, and path prefix. |
| `HelpText` | yes | Backend help description shown in `warden path-help`. |
| `FormatAccess` | yes | Builds the response body for `access/{name}`. See [The FormatAccess callback](#the-formataccess-callback). |
| `GrantFields` | optional | Provider-specific grant fields keyed by name. See [Designing GrantFields](#designing-grantfields). |

## Designing GrantFields

`GrantFields` is a `map[string]*framework.FieldSchema` declaring the database-specific knobs an operator can set on each grant. The framework merges your fields with its built-in `name` / `credential_spec` / `description`, persists what the caller writes, and exposes the values back to you in `FormatAccess` via the `grant` map.

```go
GrantFields: map[string]*framework.FieldSchema{
    "db_name": {
        Type:        framework.TypeString,
        Description: "Database name to include in the connection string",
    },
    "db_engine": {
        Type:        framework.TypeString,
        Description: "Database engine (postgres, mysql). Overrides the spec value if set.",
    },
},
```

### Constraints

- **Strings only.** `Grant` is `map[string]string` and the write handler only persists string values. Setting `Type: framework.TypeInt` will silently drop the value at write time. Encode numbers / bools as strings if you need them.
- **Do not redeclare `credential_spec` or `description`.** The framework adds them. If names collide your schema wins, but `credential_spec` is still required at write time.
- **Everything is optional from the framework's view.** Empty values are skipped during write. If a field is mandatory for your DSN, validate it inside `FormatAccess`.

### Writing a grant

The fields you declare become CLI arguments at `grants/{name}`:

```
warden write rds/grants/analytics \
    credential_spec=prod-readonly \
    db_name=analytics \
    db_engine=postgres \
    description="readonly analytics grant"
```

### Reading the values back

In `FormatAccess`, index the `grant` map by field name. A common pattern (used by RDS) is **grant overrides credential**: the credential spec carries a default, and the grant can pin it more tightly. Useful when one credential spec serves multiple grants pointing at different databases on the same server.

```go
func formatAccess(cred *credential.Credential, grant dbaccess.Grant, principal string) map[string]interface{} {
    dbName := grant["db_name"]
    engine := grant["db_engine"]
    if engine == "" {
        engine = cred.Data["db_engine"] // fall back to credential
    }
    // ...build DSN
}
```

## The FormatAccess callback

```go
type FormatAccessFunc func(cred *credential.Credential, grant Grant, principal string) map[string]interface{}
```

The framework looks up the grant, mints the credential it points to, then calls your function to shape the response body delivered to the caller.

| Argument | Source | Notes |
|----------|--------|-------|
| `cred` | The credential source driver for `grant["credential_spec"]` | `cred.Data` carries fields like `db_host`, `db_port`, `db_user`, `auth_token`, `db_engine`. The exact keys depend on the credential mint method. `cred.LeaseTTL` is the credential's lifetime. |
| `grant` | Persisted `grants/{name}` entry | A `map[string]string` containing `credential_spec`, optional `description`, and your `GrantFields`. |
| `principal` | `req.TokenEntry().PrincipalID` | Useful for tagging connections (`application_name` in PostgreSQL, `program_name` in MySQL) so DBAs can attribute load. Empty string when there is no token entry. |

Common response keys, matching what RDS and Redshift return today:

- `connection_string` — the ready-to-use DSN
- `lease_duration` — `int(cred.LeaseTTL.Seconds())`

You are free to add provider-specific fields (separate host / port / token, broker URLs, etc.) — the framework treats the returned map as opaque.

## When NOT to use dbaccess

- **You proxy database traffic.** `dbaccess` only vends DSNs; the workload connects to the database directly. If Warden needs to sit in the data path, you need a custom backend (similar to how `httpproxy` is for HTTP and not used by AWS / Azure / Vault).
- **You need non-CRUD grant operations** like revocation hooks or grant listing — those would require framework changes first.
- **Your "access" is not grant-scoped.** The framework assumes a `(grant name) -> (credential spec + db config)` mapping. If you need richer routing, build it directly on `framework.AccessBackend`.

## Existing providers using dbaccess

| Provider | Provider-specific grant fields | Engines |
|----------|--------------------------------|---------|
| [RDS](../../rds/provider.go) | `db_name`, `db_engine` | PostgreSQL, MySQL (Amazon RDS / Aurora) |
| [Redshift](../../redshift/provider.go) | `db_name` | PostgreSQL wire (provisioned clusters + serverless workgroups) |
