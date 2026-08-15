---
title: "Azure Blob"
description: "Publish the OIDC issuer's public keys to an Azure Storage container, authenticated by a service principal."
---

> `set-publisher -type=azure_blob`

Publishes the discovery + JWKS documents to an **Azure Storage** container, authenticated
by a **service principal** (Entra ID data-plane auth). Warden **self-rotates** the service
principal's client secret via Microsoft Graph.

```bash
warden oidc-issuer set-publisher -type=azure_blob -rotation-period=720h \
  -config=account_name=wardenoidc -config=container=jwks \
  -config=tenant_id=<tenant> -config=client_id=<app-id> \
  -config=client_secret=@/run/secrets/sp -config=secret_id=<keyId>
```

A Shared Key / `account_key` is **not** supported, and sovereign clouds are not yet
supported (the OAuth authority and Graph host are the public-cloud endpoints). Self-rotation
requires the service principal to hold **Storage Blob Data Contributor** on the container
and Graph rights to manage its own app registration (`Application.ReadWrite.OwnedBy` as an
owner, or `Application.ReadWrite.All`).

## Parameters

| Key | Required | Description |
|---|---|---|
| `account_name` | yes | Storage account name. |
| `container` | yes | Blob container. |
| `tenant_id` | yes | Entra tenant ID. |
| `client_id` | yes | Service-principal (app) client ID. |
| `client_secret` | yes | Service-principal client secret (masked; use `@file`). |
| `secret_id` | no | Graph password-credential id (`keyId`) of the current secret — set it when `rotation_period` is used, so rotation can retire the superseded secret. |
| `prefix` | no | Blob-name prefix. |
| `endpoint` | no | Blob service URL override (private endpoint or emulator). |
| `rotation_period` | no | Self-rotate the client secret on this cadence (minimum 24h). |

## See also

- [Publishers](/federation/publishers/) — what a publisher does and the two rotations.
- [`warden oidc-issuer`](/cli/oidc-issuer/) — the CLI.
