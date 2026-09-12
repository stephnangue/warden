## Warden v0.20.0

v0.20.0 is the **agent-and-user authorization** release. Warden has carried two principals per request since v0.19.0, but only one of them could be reasoned about: the agent authorized the request and the user was along for attribution. That changes here. The **user principal is now visible to the policy layer**, so a condition can require a human behind the agent — and, more importantly, require that *this* agent is the one the human authorized. The CEL `token` namespace is renamed **`agent`** to say plainly which principal a rule is talking about, and a new **`user`** namespace sits beside it.

Two consequences follow. A denial that a user could remedy no longer looks like a wall: Warden answers **`401` with a `WWW-Authenticate` challenge** and publishes **RFC 9728 protected resource metadata**, so a client discovers where to authenticate the person and retries. And **MCP authorization becomes its own policy type** — capability policies govern paths, MCP policies govern calls, and access is the intersection of both. MCP traffic with no MCP policy in scope is now **denied** rather than passing unrestricted.

On the credential side, keyless keeps widening: **Alibaba Cloud** and **Kubernetes** federate, **AWS Secrets Manager** and **GCP Secret Manager** join OpenBao/Vault as chaining producers, and a client assertion can now be **signed inside a KMS** that Warden never sees the key for.

**Eight breaking changes — read Upgrading before you bump.** Two of them can take a working deployment down if you roll the binary out first and migrate afterwards.

### Breaking Changes

- **The CEL `token` namespace is now `agent`.** No alias. A stored policy referencing `token` fails to compile at load, and because policies are re-parsed on read, it **cannot be read back afterwards** — export your policy texts first. Audit `salt_fields` selectors move with it, and a stale one does not error: it stops matching, and the value it protected **begins logging in clear**.
- **Dual-token extraction.** On a `user_auth_path` mount the legs swap: `Authorization` carries the **user**, the agent moves to `X-Warden-Agent-Token` or a client certificate. `user_token_header` is retired and `user_auth_path` is mount-only.
- **MCP rules move to `sys/policies/mcp/<name>`.** A nested `mcp { }` block is rejected at parse, the grammar becomes family blocks, and `allowed_params` / `denied_params` give way to a CEL condition over `call.args`.
- **MCP traffic with no MCP policy in scope is denied** (`no_mcp_policy`). Mounts meant to stay open need an explicit wildcard policy.
- **`mcp` / `mcp_aws` `timeout` defaults to 60 seconds** and now caps a single call; long-lived streams answer to the new `listen_timeout`.
- **IBM `iam_with_cos`, OVH `dynamic_s3` and `oauth2_token_and_s3` are removed**, replaced by `access_keys` sourced through `secret_spec`. Drain OVH leased pairs before upgrading.
- **`apikey` sources rename `optional_metadata` to `credential_fields`** — and the mechanism now works, where before the declared fields silently never reached the provider.

### New Features

**Agent and user in policy**

- **The user principal reaches CEL.** A `user` namespace beside `agent`, carrying the same fields minus `policies` — the user never authorizes, so it cannot widen what an agent may do, only be made required.
- **Binding an agent to the user it acts for.** It is not enough that both are present; the user must be paired with *this* agent. The pairing is attested on the user's token by an RFC 8693 claim — `may_act` where the IdP pre-authorizes an agent, `act` where the credential is itself a delegation token — and either maps through a JSON Pointer.
- **`401` instead of `403` when a user would fix it**, with a `resource_metadata` parameter, plus **RFC 9728 protected resource metadata** and a `warden protected-resource` command to configure it. A retry that still fails gets a terminal `403`; the exchange cannot loop.

**MCP**

- **A first-class MCP policy type** with its own grammar, storage and `-type` flag, composing with capability policies as an intersection.
- **Protocol hardening**: per-URI gating for `subscriptions/listen`, transport headers validated against the body, modern-era batches refused, per-principal responses marked uncacheable.

**Credentials**

- **Keyless federation for Alibaba Cloud and Kubernetes** — the latter presents its assertion directly as the bearer token, with no exchange hop.
- **AWS and GCP secret stores can produce chained secrets** (`mint_method=secret_read`), and can be federated themselves, so a chain is keyless at both hops.
- **KMS-signed client assertions** (`client_auth=kms_private_key_jwt`) fed by **`transit_signer`**, which mints a scoped signing capability rather than key material — the private key is read by nobody, including Warden.
- **Nine more drivers can chain their standing secret**, and claim templating now reaches AWS `secret_id` and GCP `secret_name` alongside Vault's `secret_path`, so one spec can resolve a different secret per caller.
- **The `honeycomb` credential driver is removed** — its keys could be neither revoked nor expired. Hold the key in a vault and chain it. The honeycomb *provider* is unaffected.

### Fixed

- **`cas_required` is enforced** on the policy write path, which never applied it — a policy that set it was unguarded. Refusals answer `4xx`, not `500`.
- **Responses longer than 10 seconds survive.** A hardcoded listener write timeout severed every response over ~10s, so no LLM mount could reach its 120-second budget; raising the mount `timeout` did nothing. The listener's HTTP timeouts are configurable now, and streaming sheds them.
- **Denied requests are audited once**, not twice.

### Upgrading

Eight changes need action. Work through [Upgrading from v0.19.0](https://wardengateway.com/upgrade/from-v0-19/) **before** rolling out the binary — the first two steps are irreversible once it is running.

- **Export every policy that uses a `token.*` condition** — after the upgrade it cannot be read back:
  ```bash
  for name in $(warden policy list -o text); do
    warden policy read -o table "$name" > "policy-backup-$name.hcl"
  done
  ```
- **Snapshot your audit configuration** and rewrite `salt_fields` selectors to the `agent` namespace, or the values they protect begin logging in clear.
- **Drain OVH leased credential pairs**, which are not cleaned up after the upgrade.
- Then: rewrite `token.*` conditions, re-express `mcp { }` blocks as `-type=mcp` policies and attach them to the roles that need them, add wildcard MCP policies to mounts meant to stay open, set `timeout` explicitly on MCP mounts with long calls, move agents to `X-Warden-Agent-Token`, and rename `optional_metadata` to `credential_fields`.
