---
name: rds
description: "Get a short-lived database connection string for AWS RDS through Warden — agent connects to the DB directly with a 15-min IAM auth token."
category: provider-guide
upstream: AWS RDS (PostgreSQL, MySQL)
---

# RDS through Warden

## What it does

**Different mental model from gateway providers.** Warden mints a
short-lived IAM authentication token for an RDS instance, packs it
into a connection string with the host/port/db/user, and returns
that to the agent. **The agent then connects to the RDS endpoint
directly** — Warden is *not* in the data path.

Use case: agents that need to run SQL against an RDS instance, with
auth scoped to a Warden role rather than a long-lived DB password.

## Configure the CLI/SDK

The Warden call returns a *connection string* you feed to your
PostgreSQL or MySQL client unchanged. There's no SDK setup; this is
a single HTTP call followed by a regular DB connection.

`<mount>` and `<grant-name>` below come from the discovery flow plus
one extra step:
- `<mount>` is the chosen provider's path from `warden list sys/providers`
  (e.g. `rds/`, `rds-prod/`, `pg-warehouse/`).
- `<grant-name>` is a pre-configured grant (operator decides which
  RDS instance + DB user + capabilities each grant exposes). List them
  with `warden list <mount>/access` and pick by description.

The role from `warden roles` is implicit here — RDS is transparent-only,
so the JWT itself selects the role; there's no per-call role flag.

```bash
URL pattern : $WARDEN_ADDR/v1/<mount>/access/<grant-name>
Auth header : Authorization: Bearer <JWT>
```

## Examples

(All examples assume mount `rds-prod/`; substitute yours.)

```bash
# Mint a connection string
RESP=$(curl -sH "Authorization: Bearer $JWT" \
  $WARDEN_ADDR/v1/rds-prod/access/analytics-reader)

# {"connection_string":"host=db.example.com port=5432 dbname=analytics user=ro_user password=eyJ...IAM-TOKEN... sslmode=require","lease_duration":900}

CONN=$(echo $RESP | jq -r .connection_string)
TTL=$(echo $RESP | jq -r .lease_duration)

# Use directly (PostgreSQL)
psql "$CONN" -c "SELECT count(*) FROM events WHERE day = current_date;"
```

MySQL grant looks slightly different — same response shape, the
connection string is in MySQL DSN form:

```bash
# {"connection_string":"ro_user:eyJ...IAM...@tcp(db.example.com:3306)/analytics?tls=true&...","lease_duration":900}

mysql --defaults-extra-file=<(echo "[client]"; echo "user=...") ...
```

For Python, parse the connection string into your client's connect
args; for Go, pass it to `database/sql`'s `Open`. The returned
string follows the engine's standard DSN format.

## TTL semantics

The IAM token in the connection string is used at **connection
establishment time** only. Once the DB connection is open, it stays
open until *you* close it — token expiry doesn't terminate an
existing session.

The token is valid for **15 minutes** (the `lease_duration` in the
response, in seconds, is typically 900). That window is your budget
for *opening* the connection, not for keeping it open. If you need
to open a *new* connection later (the old one was closed, dropped,
or you're spinning up a new worker), call `…/access/<grant>` again
to get a fresh token-bearing connection string.

## Quirks

- **No request proxying.** Warden returns a string and steps out of
  the data path. The DB endpoint must be reachable from the agent's
  network; Warden doesn't tunnel it.
- **Grants are pre-configured by the operator.** Agents can't create
  grants via this provider — only consume existing ones. Use
  `warden list <mount>/access` to see what's available.
- **`rds_iam_token` is the underlying mint method.** RDS instances
  must have IAM database authentication enabled and the DB user
  pre-created with `rds_iam` group membership.
- **Connection failures are not Warden's responsibility.** A
  successful mint followed by a connection error means the DB
  endpoint, security group, or DB user is misconfigured — diagnose
  on the RDS side, not on Warden.

