# Providers

Warden supports 32 providers across LLMs, cloud, observability, code hosting, secrets, and more. Follow the link for each provider to configure your endpoint.

Status: ✅ available, 🔜 on the roadmap.

## LLM APIs

| Provider | Warden does | Status |
|---|---|---|
| [Anthropic](../provider/anthropic/README.md) | Injects `x-api-key` | ✅ |
| [OpenAI](../provider/openai/README.md) | Injects `Authorization: Bearer` API key | ✅ |
| [Mistral](../provider/mistral/README.md) | Injects `Authorization: Bearer` API key | ✅ |
| [Cohere](../provider/cohere/README.md) | Injects `Authorization: Bearer` API token | ✅ |

## Cloud infrastructure

| Provider | Warden does | Status |
|---|---|---|
| [AWS](../provider/aws/README.md) | Re-signs requests with temporary STS credentials | ✅ |
| [Alicloud](../provider/alicloud/README.md) | Proxies Alicloud OpenAPI (ACS3) and OSS (S3-compatible), re-signing with STS AssumeRole credentials | ✅ |
| [Azure](../provider/azure/README.md) | Issues Microsoft Entra ID Bearer tokens | ✅ |
| [GCP](../provider/gcp/README.md) | Issues temporary access tokens | ✅ |
| [IBM Cloud](../provider/ibmcloud/README.md) | Issues IAM Bearer tokens | ✅ |
| [OVH](../provider/ovh/README.md) | Injects Bearer token | ✅ |
| [Scaleway](../provider/scaleway/README.md) | Injects Bearer token | ✅ |
| [Cloudflare](../provider/cloudflare/README.md) | Injects Bearer token (API and Logpush) | ✅ |

## Code hosting & CI/CD

| Provider | Warden does | Status |
|---|---|---|
| [GitHub](../provider/github/README.md) | Injects GitHub App installation token or PAT | ✅ |
| [GitLab](../provider/gitlab/README.md) | Injects access token | ✅ |
| [Atlassian](../provider/atlassian/README.md) | Injects token (Jira, Bitbucket) | ✅ |
| [Ansible Tower](../provider/ansible_tower/README.md) | Injects Bearer token | ✅ |
| [Terraform Enterprise](../provider/tfe/README.md) | Injects Bearer token | ✅ |

## Observability

| Provider | Warden does | Status |
|---|---|---|
| [Datadog](../provider/datadog/README.md) | Injects `DD-API-KEY` and `DD-APPLICATION-KEY` | ✅ |
| [Dynatrace](../provider/dynatrace/README.md) | Injects credentials | ✅ |
| [Elastic](../provider/elastic/README.md) | Injects basic auth or token (Elasticsearch, Kibana) | ✅ |
| [Grafana](../provider/grafana/README.md) | Injects Bearer token (Grafana, Loki, Mimir, Tempo, Pyroscope) | ✅ |
| [Honeycomb](../provider/honeycomb/README.md) | Injects Bearer token | ✅ |
| [New Relic](../provider/newrelic/README.md) | Injects `Api-Key` header | ✅ |
| [Prometheus](../provider/prometheus/README.md) | Proxies API | ✅ |
| [Sentry](../provider/sentry/README.md) | Injects Bearer token | ✅ |
| [Splunk](../provider/splunk/README.md) | Injects Bearer token | ✅ |

## Incident & ITSM

| Provider | Warden does | Status |
|---|---|---|
| [PagerDuty](../provider/pagerduty/README.md) | Injects Bearer token | ✅ |
| [ServiceNow](../provider/servicenow/README.md) | Injects Bearer token | ✅ |
| [Slack](../provider/slack/README.md) | Injects Bearer token | ✅ |

## Infrastructure automation

| Provider | Warden does | Status |
|---|---|---|
| [Kubernetes](../provider/kubernetes/README.md) | Injects service account token | ✅ |

## Secrets

| Provider | Warden does | Status |
|---|---|---|
| [HashiCorp Vault / OpenBao](../provider/vault/README.md) | Mints short-lived Vault tokens | ✅ |

## Databases

| Provider | Warden does | Status |
|---|---|---|
| [AWS RDS / Aurora](../provider/rds/README.md) | Issues IAM database auth token | 🔜 |
| AWS Redshift | Issues IAM database auth token | 🔜 |
| GCP Cloud SQL | Issues IAM database auth token | 🔜 |
| Azure SQL | Issues Entra database auth token | 🔜 |
| Snowflake | Issues database auth token | 🔜 |

## Object storage

| Provider | Warden does | Status |
|---|---|---|
| AWS S3 | Issues pre-signed URL | 🔜 |
| GCP Cloud Storage | Issues pre-signed URL | 🔜 |
| Azure Blob Storage | Issues pre-signed URL | 🔜 |


