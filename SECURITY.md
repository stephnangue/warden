# Security Policy

Warden sits between agents and the systems they act on: it verifies who is
calling, decides each request by policy, and holds the credentials for the
upstream services. A flaw that weakens any of these is a security issue. Please
report it privately.

## Reporting a vulnerability

Report it through GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/stephnangue/warden/security/advisories/new),
or the **Security** tab → **Advisories** → **Report a vulnerability**.

Do not open a public issue, pull request or discussion about a suspected
vulnerability.

A useful report includes:

- the Warden version (`warden --version`) or commit, and how it runs: binary,
  container image or Helm chart;
- the part affected: an auth method, a provider, policies, namespaces, audit,
  the command-line client;
- the configuration needed to reproduce it, with secrets removed;
- the steps or a proof of concept, and what an attacker gains.

If you have had no acknowledgement after 3 business days, open a public issue
that says only that you sent a report, with no detail, so the maintainer knows
to check the advisories.

## What to expect

Warden has one maintainer. These are targets, not guarantees:

| Step | Target |
|---|---|
| Acknowledge the report | 3 business days |
| Confirm or decline it, with a severity (CVSS) | 10 business days |
| Release a fix for a critical or high severity issue | 30 days after confirming it |
| Release a fix for a medium or low severity issue | The next release |

The fix is developed in private, and you are welcome to review it. When the
fixed release is out, we publish a GitHub Security Advisory, request a CVE for
it, and credit you unless you ask us not to.

Please keep the issue private until the advisory is published, or for 90 days
after your report, whichever comes first. If we need longer, we will tell you
why before the 90 days are up.

## Supported versions

Warden is not yet at 1.0 and releases about once a month. Every security fix
ships in the next release. A fix for a critical or high severity issue also
ships sooner, as a patch release of the latest minor version. Older minor
versions get no fixes: upgrade to the latest release.

| Version | Security fixes |
|---|---|
| The latest minor release | Yes |
| Older | No |

## Scope

In scope: the `warden` server and command-line client, the container images at
`ghcr.io/stephnangue/warden`, the Helm chart, the release downloads, and the
install script at `https://wardengateway.com/install.sh`. For example:

- a request granted when policy should refuse it, or a role granted to a caller
  that should not get it;
- getting past authentication, or one identity taken for another: an agent
  acting as a different agent, a token or ticket accepted for the wrong
  audience or namespace;
- an upstream credential, signing key or token reaching a caller, a log or an
  audit entry;
- reaching from one namespace into another;
- a caller with no credential using up the server's CPU or memory;
- a granted request missing from the audit log;
- dev-mode behavior reachable on a server not started with `-dev`.

Out of scope:

- dev mode itself (`-dev`, `-dev-root-token`, `-dev-playground`), which is
  insecure on purpose;
- actions taken with operator privileges, such as the root token or the
  `warden-admin` role, that behave as documented;
- flaws in the upstream services Warden gives agents access to;
- scanner output with no shown impact on Warden. A dependency CVE in code
  Warden never reaches can be filed as a normal issue.

If the flaw is in one of Warden's dependencies, report it here anyway; we
coordinate with its maintainers.

## Safe harbor

We welcome good-faith research that follows this policy and will not take
legal action over it. While testing:

- test only deployments you own or are allowed to test;
- do not access, change or keep other people's data;
- do not run denial-of-service tests against systems you do not own, including
  wardengateway.com;
- do not use social engineering or physical attacks.

Warden has no bug bounty program.
