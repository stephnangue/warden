---
title: "Provider Backends"
---

A **provider backend** is a mounted gateway that fronts an upstream system — an
LLM API, a cloud control plane, a Git host, an observability platform. A workload
sends its request to the Warden mount as if Warden were the upstream; Warden
authenticates the caller, checks [policy](/concepts/policies/), injects the
right [credential](/concepts/credentials/), and proxies the call through. See
[Providers](/concepts/providers/) for the gateway model and how a request
flows.

Each page below is a setup guide for one provider — prerequisites, mount
configuration, credential sources and specs, policy, and a configuration
reference.

## MCP servers

| Provider | Description |
|---|---|
| [Generic](/provider-backends/mcp/) | Any bearer-authenticated Model Context Protocol server. Per-upstream recipes: [GitHub](/provider-backends/mcp-github/), [Slack](/provider-backends/mcp-slack/), Cloudflare, … |
| [AWS](/provider-backends/mcp_aws/) | AWS's hosted Model Context Protocol server |

## LLM APIs

| Provider | Description |
|---|---|
| [Anthropic](/provider-backends/anthropic/) | Claude models — messages, chat, and embeddings |
| [OpenAI](/provider-backends/openai/) | GPT models — chat, embeddings, and moderation |
| [Mistral](/provider-backends/mistral/) | Mistral chat and embeddings models |
| [Cohere](/provider-backends/cohere/) | Cohere generation, embeddings, and rerank models |

## Cloud infrastructure

| Provider | Description |
|---|---|
| [AWS](/provider-backends/aws/) | Amazon Web Services control plane and service APIs |
| [Alicloud](/provider-backends/alicloud/) | Alibaba Cloud OpenAPI (ACS3) and OSS object storage |
| [Azure](/provider-backends/azure/) | Microsoft Azure resource management and services |
| [GCP](/provider-backends/gcp/) | Google Cloud Platform APIs |
| [IBM Cloud](/provider-backends/ibmcloud/) | IBM Cloud platform services |
| [OVH](/provider-backends/ovh/) | OVHcloud public cloud and hosting APIs |
| [Scaleway](/provider-backends/scaleway/) | Scaleway cloud platform APIs |
| [Cloudflare](/provider-backends/cloudflare/) | Cloudflare edge platform — API and Logpush |

## Code hosting & CI/CD

| Provider | Description |
|---|---|
| [GitHub](/provider-backends/github/) | GitHub REST API and Git over HTTPS |
| [GitLab](/provider-backends/gitlab/) | GitLab REST API and Git over HTTPS |
| [Atlassian](/provider-backends/atlassian/) | Atlassian Jira and Bitbucket |
| [Ansible Tower](/provider-backends/ansible_tower/) | Ansible Automation Platform (AWX / Tower) |
| [Terraform Enterprise](/provider-backends/tfe/) | Terraform Enterprise / Cloud API |

## Observability

| Provider | Description |
|---|---|
| [Datadog](/provider-backends/datadog/) | Datadog metrics, logs, and monitoring |
| [Dynatrace](/provider-backends/dynatrace/) | Dynatrace observability platform |
| [Elastic](/provider-backends/elastic/) | Elasticsearch and Kibana |
| [Grafana](/provider-backends/grafana/) | Grafana, Loki, Mimir, Tempo, and Pyroscope |
| [Honeycomb](/provider-backends/honeycomb/) | Honeycomb observability and tracing |
| [New Relic](/provider-backends/newrelic/) | New Relic observability platform |
| [Prometheus](/provider-backends/prometheus/) | Prometheus metrics query API |
| [Sentry](/provider-backends/sentry/) | Sentry error and performance monitoring |
| [Splunk](/provider-backends/splunk/) | Splunk logging and search platform |

## Incident & ITSM

| Provider | Description |
|---|---|
| [PagerDuty](/provider-backends/pagerduty/) | PagerDuty incident response platform |
| [ServiceNow](/provider-backends/servicenow/) | ServiceNow ITSM platform |
| [Slack](/provider-backends/slack/) | Slack messaging and Web API |

## Infrastructure automation

| Provider | Description |
|---|---|
| [Kubernetes](/provider-backends/kubernetes/) | Kubernetes API server |

## Secrets

| Provider | Description |
|---|---|
| [HashiCorp Vault / OpenBao](/provider-backends/vault/) | HashiCorp Vault / OpenBao secrets platform |


## Generic

| Provider | Description |
|---|---|
| [REST](/provider-backends/rest/) | Any single-token REST API, fronted through configuration alone — no bespoke provider code |

## See Also

- [Providers](/concepts/providers/) — the gateway model: how a request is authenticated, authorized, and proxied.
- [Credentials](/concepts/credentials/) — what each provider injects into the proxied request.
- [Roles](/concepts/roles/) — how the role on a request selects access and credential.
- [`warden provider`](/cli/provider/) — the CLI for enabling, listing, tuning, and disabling providers.
- [Concepts](/concepts/) — how Warden works, end to end.
</content>
