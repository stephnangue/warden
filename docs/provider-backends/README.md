# Provider Backends

A **provider backend** is a mounted gateway that fronts an upstream system — an
LLM API, a cloud control plane, a Git host, an observability platform. A workload
sends its request to the Warden mount as if Warden were the upstream; Warden
authenticates the caller, checks [policy](../concepts/policies.md), injects the
right [credential](../concepts/credentials.md), and proxies the call through. See
[Providers](../concepts/providers.md) for the gateway model and how a request
flows.

Each page below is a setup guide for one provider — prerequisites, mount
configuration, credential sources and specs, policy, and a configuration
reference.

## MCP servers

| Provider | Description |
|---|---|
| [Generic](mcp.md) | Any bearer-authenticated Model Context Protocol server. Per-upstream recipes: [GitHub](mcp-github.md), [Slack](mcp-slack.md), Cloudflare, … |
| [AWS](mcp_aws.md) | AWS's hosted Model Context Protocol server |

## LLM APIs

| Provider | Description |
|---|---|
| [Anthropic](anthropic.md) | Claude models — messages, chat, and embeddings |
| [OpenAI](openai.md) | GPT models — chat, embeddings, and moderation |
| [Mistral](mistral.md) | Mistral chat and embeddings models |
| [Cohere](cohere.md) | Cohere generation, embeddings, and rerank models |

## Cloud infrastructure

| Provider | Description |
|---|---|
| [AWS](aws.md) | Amazon Web Services control plane and service APIs |
| [Alicloud](alicloud.md) | Alibaba Cloud OpenAPI (ACS3) and OSS object storage |
| [Azure](azure.md) | Microsoft Azure resource management and services |
| [GCP](gcp.md) | Google Cloud Platform APIs |
| [IBM Cloud](ibmcloud.md) | IBM Cloud platform services |
| [OVH](ovh.md) | OVHcloud public cloud and hosting APIs |
| [Scaleway](scaleway.md) | Scaleway cloud platform APIs |
| [Cloudflare](cloudflare.md) | Cloudflare edge platform — API and Logpush |

## Code hosting & CI/CD

| Provider | Description |
|---|---|
| [GitHub](github.md) | GitHub REST API and Git over HTTPS |
| [GitLab](gitlab.md) | GitLab REST API and Git over HTTPS |
| [Atlassian](atlassian.md) | Atlassian Jira and Bitbucket |
| [Ansible Tower](ansible_tower.md) | Ansible Automation Platform (AWX / Tower) |
| [Terraform Enterprise](tfe.md) | Terraform Enterprise / Cloud API |

## Observability

| Provider | Description |
|---|---|
| [Datadog](datadog.md) | Datadog metrics, logs, and monitoring |
| [Dynatrace](dynatrace.md) | Dynatrace observability platform |
| [Elastic](elastic.md) | Elasticsearch and Kibana |
| [Grafana](grafana.md) | Grafana, Loki, Mimir, Tempo, and Pyroscope |
| [Honeycomb](honeycomb.md) | Honeycomb observability and tracing |
| [New Relic](newrelic.md) | New Relic observability platform |
| [Prometheus](prometheus.md) | Prometheus metrics query API |
| [Sentry](sentry.md) | Sentry error and performance monitoring |
| [Splunk](splunk.md) | Splunk logging and search platform |

## Incident & ITSM

| Provider | Description |
|---|---|
| [PagerDuty](pagerduty.md) | PagerDuty incident response platform |
| [ServiceNow](servicenow.md) | ServiceNow ITSM platform |
| [Slack](slack.md) | Slack messaging and Web API |

## Infrastructure automation

| Provider | Description |
|---|---|
| [Kubernetes](kubernetes.md) | Kubernetes API server |

## Secrets

| Provider | Description |
|---|---|
| [HashiCorp Vault / OpenBao](vault.md) | HashiCorp Vault / OpenBao secrets platform |


## Generic

| Provider | Description |
|---|---|
| [REST](rest.md) | Any single-token REST API, fronted through configuration alone — no bespoke provider code |

## See Also

- [Providers](../concepts/providers.md) — the gateway model: how a request is authenticated, authorized, and proxied.
- [Credentials](../concepts/credentials.md) — what each provider injects into the proxied request.
- [Roles](../concepts/roles.md) — how the role on a request selects access and credential.
- [`warden provider`](../cli/provider.md) — the CLI for enabling, listing, tuning, and disabling providers.
- [Concepts](../concepts/README.md) — how Warden works, end to end.
</content>
