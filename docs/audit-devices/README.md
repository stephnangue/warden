# Audit Devices

An **audit device** is a pluggable sink that receives the formatted request and
response entries Warden produces for every operation, and writes them to a
destination you control. Enabling at least one device is what turns the
[audit log](../concepts/audit.md) from a concept into a forensic record — and what
flips Warden from fail-open to fail-closed, so a request is served only if it can
be audited.

This section is the operational counterpart to the [Audit](../concepts/audit.md)
concept page. The concept page explains *what* gets recorded, how secrets are
HMAC-salted, and the fail-open→fail-closed guarantee; the pages here are setup
guides — how to enable, configure, tune, and troubleshoot each device.

Warden ships one device. The page below is a setup guide — enabling it three ways
(CLI, declarative HCL, HTTP API), a full configuration reference, rotation and
retention, and troubleshooting.

| Device | Writes | Reach for it when |
|--------|--------|-------------------|
| [File](file.md) | JSON-lines to a local file, with size- and time-based rotation | you want a durable on-disk audit trail you can tail, rotate, and ship to a SIEM or log collector. |

Audit devices live in the **root namespace** and are **global**: every namespace's
traffic is logged to the same devices, and each entry records the namespace it came
from. Managing devices is therefore a root-namespace, operator-level operation.

## See Also

- [Audit](../concepts/audit.md) — the recording model: what's logged, HMAC salting, and fail-open/closed.
- [Policies](../concepts/policies.md) — the authorization decisions recorded in each entry.
- [Credentials](../concepts/credentials.md) — what "credential issued" in the log refers to.
- [Audit Attribution](../use-cases/audit-attribution.md) — tying every request back to an identity.
- [Concepts](../concepts/README.md) — how Warden works, end to end.
