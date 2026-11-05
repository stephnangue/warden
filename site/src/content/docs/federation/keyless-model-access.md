---
title: "Keyless model access"
description: "Call Amazon Bedrock, Vertex AI and Azure OpenAI through Warden's cloud providers, with no model API key stored anywhere."
---

The three clouds' model APIs need no API key. Each accepts the cloud's own short-lived
credential, and Warden's cloud providers already mint that credential through
[keyless federation](/federation/keyless-credentials/): Warden presents a short-lived
identity assertion, the cloud issues a credential, and Warden adds it to the request.
The agent holds only its own identity, and Warden stores no key.

| Model API | Warden provider | Credential the request carries | How it is keyless |
|---|---|---|---|
| Amazon Bedrock Runtime | [`aws`](/provider-backends/aws/) | Temporary AWS keys; Warden re-signs the request with SigV4 | `aws` source, `auth_method=oidc_federation`, `sts_assume_role` |
| Google Vertex AI | [`gcp`](/provider-backends/gcp/) | A Google access token | `gcp` source, `auth_method=oidc_federation`, Workload Identity Federation |
| Azure OpenAI | [`azure`](/provider-backends/azure/) | An Entra token for `https://cognitiveservices.azure.com/` | `azure` source, `auth_method=oidc_federation`, `bearer_token` |

Model APIs that take a plain API key (Gemini on the generative-language endpoint, Groq,
Together AI and others) go through a [`rest`](/provider-backends/rest/#llm-apis) mount
instead. The key is then stored, or chained from a secret store.

## Before you start

- A JWT auth mount at `auth/jwt/`, set up as in [JWT auth](/auth-methods/jwt/). The agent
  presents a token from it on every call; see
  [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt).
- The cloud trusts Warden's issuer. [Keyless credentials](/federation/keyless-credentials/)
  covers the IAM OIDC provider for AWS, the Workload Identity pool for GCP and the
  federated credential for Entra.

Each section below mounts a provider for one model API, creates the source, spec and
policy, then a role and a group that grants it to the agents of the JWT mount.

## Amazon Bedrock

The `aws` provider sends Bedrock Runtime calls to the runtime endpoint,
`bedrock-runtime.<region>.amazonaws.com`, though Bedrock signs them with the control
plane's service name. `converse` and `converse-stream` have been run against a real
account through it; `invoke-model`, its streaming form and the guardrail calls are routed
the same way. The model id's `:` and an inference-profile ARN's `/` are forwarded as the
client escaped them.

Mount a provider for the model API alone, with a long `timeout`:

```bash
warden provider enable -path=bedrock -description="Amazon Bedrock models for agents" aws

warden write bedrock/config '{
  "proxy_domains": ["localhost"],
  "timeout": "300s",
  "max_body_size": 20971520,
  "auto_auth_path": "auth/jwt/",
  "default_role": "bedrock-user"
}'
```

The keyless source and a spec that assumes the role allowed to invoke models:

```bash
warden cred source create aws-fed -json '{
  "type": "aws",
  "config": {
    "auth_method": "oidc_federation",
    "region": "us-east-1",
    "audience": "sts.amazonaws.com"
  }
}'

warden cred spec create bedrock-invoke -json '{
  "source": "aws-fed",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "sts_assume_role",
    "subject_token_source": "warden_identity",
    "role_arn": "arn:aws:iam::<ACCOUNT_ID>:role/warden-bedrock-invoke",
    "ttl": "1h"
  }
}'
```

The IAM role's trust policy allows `sts:AssumeRoleWithWebIdentity` and `sts:TagSession`
from Warden's issuer, as on the [AWS page](/provider-backends/aws/#3a-keyless-federation-recommended).
Its permissions grant `bedrock:InvokeModel`, which `converse` needs, and
`bedrock:InvokeModelWithResponseStream`, which `converse-stream` needs.

A policy that allows one model, then the role and the group:

```bash
warden policy write bedrock-invoke - <<EOF
path "bedrock/gateway/model/amazon.nova-micro-v1:0/*" {
  capabilities = ["create", "update"]
}
EOF

warden role create bedrock-user -json '{
  "policies": ["bedrock-invoke"],
  "cred_spec_name": "bedrock-invoke",
  "provider_path": "bedrock/"
}'

warden identity group create bedrock-user-agents -json '{
  "type": "virtual",
  "roles": ["bedrock-user"],
  "rules": [
    { "mount": ["auth/jwt/"] }
  ]
}'
```

On the agent side, the role name goes in `AWS_ACCESS_KEY_ID` and the JWT in both secret
slots, as for any AWS service:

```bash
export AWS_ACCESS_KEY_ID="bedrock-user"
export AWS_SECRET_ACCESS_KEY="$JWT"
export AWS_SESSION_TOKEN="$JWT"
export AWS_ENDPOINT_URL="http://localhost:8400/v1/bedrock/gateway"

aws bedrock-runtime converse --region us-east-1 \
    --model-id amazon.nova-micro-v1:0 \
    --messages '[{"role": "user", "content": [{"text": "Say hi"}]}]'
```

The AWS CLI has no command for the event-stream calls. Use an SDK for `converse-stream`,
for example boto3 with the same environment:

```python
import boto3

client = boto3.client("bedrock-runtime", region_name="us-east-1")
resp = client.converse_stream(
    modelId="amazon.nova-micro-v1:0",
    messages=[{"role": "user", "content": [{"text": "Say hi"}]}],
)
for event in resp["stream"]:
    if "contentBlockDelta" in event:
        print(event["contentBlockDelta"]["delta"]["text"], end="")
```

Bedrock has more services that sign as `bedrock`. `bedrock-agent`,
`bedrock-agent-runtime` (agents, knowledge bases, flows) and
`bedrock-data-automation(-runtime)` are not supported, and neither is
`InvokeModelWithBidirectionalStream`.

## Vertex AI

:::caution[Not yet verified]
This setup has not been run against a real Google Cloud project yet. It uses only keys
the `gcp` provider and driver accept, but treat it as the intended setup.

The `gcp` provider takes the upstream host from the path, so a Vertex call goes to
`/v1/<mount>/role/<role>/gateway/<region>-aiplatform.googleapis.com/...`. That host is
under the default `allowed_host_suffixes`, `.googleapis.com`.

```bash
warden provider enable -path=vertex -description="Vertex AI models for agents" gcp

warden write vertex/config '{
  "auto_auth_path": "auth/jwt/",
  "timeout": "300s"
}'

warden cred source create gcp-fed -json '{
  "type": "gcp",
  "config": {
    "auth_method": "oidc_federation",
    "workload_identity_provider": "//iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/warden-pool/providers/warden-oidc"
  }
}'

warden cred spec create vertex-invoke -json '{
  "source": "gcp-fed",
  "min_ttl": 300,
  "max_ttl": 3600,
  "config": {
    "mint_method": "impersonated_access_token",
    "subject_token_source": "warden_identity",
    "target_service_account": "vertex-invoker@my-project.iam.gserviceaccount.com",
    "scopes": "https://www.googleapis.com/auth/cloud-platform"
  }
}'

warden policy write vertex-invoke - <<EOF
path "vertex/role/+/gateway/us-central1-aiplatform.googleapis.com/v1/projects/my-project/locations/us-central1/publishers/google/models/gemini-2.5-flash:*" {
  capabilities = ["create", "update"]
}
EOF

warden role create vertex-user -json '{
  "policies": ["vertex-invoke"],
  "cred_spec_name": "vertex-invoke",
  "provider_path": "vertex/"
}'

warden identity group create vertex-user-agents -json '{
  "type": "virtual",
  "roles": ["vertex-user"],
  "rules": [
    { "mount": ["auth/jwt/"] }
  ]
}'

curl "${WARDEN_ADDR}/v1/vertex/role/vertex-user/gateway/us-central1-aiplatform.googleapis.com/v1/projects/my-project/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent" \
    -H "Authorization: Bearer ${JWT}" \
    -H "Content-Type: application/json" \
    -d '{
      "contents": [
        { "role": "user", "parts": [{ "text": "Say hi" }] }
      ]
    }'
```

The service account needs `roles/aiplatform.user`. The pool's principals need
`roles/iam.workloadIdentityUser` on it, as on the [GCP page](/provider-backends/gcp/#3a-keyless-federation-recommended).
:::

## Azure OpenAI

:::caution[Not yet verified]
This setup has not been run against a real Azure tenant yet. It uses only keys the
`azure` provider and driver accept, but treat it as the intended setup.

The `azure` provider takes the upstream host from the path. `<resource>.openai.azure.com`,
`<resource>.cognitiveservices.azure.com` and `<resource>.services.ai.azure.com` (AI
Foundry) are under the default `allowed_host_suffixes`.

```bash
warden provider enable -path=azure-openai -description="Azure OpenAI models for agents" azure

warden write azure-openai/config '{
  "auto_auth_path": "auth/jwt/",
  "timeout": "300s"
}'

warden cred source create azure-fed -json '{
  "type": "azure",
  "config": {
    "auth_method": "oidc_federation"
  }
}'

warden cred spec create azure-openai-invoke -json '{
  "source": "azure-fed",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "bearer_token",
    "subject_token_source": "warden_identity",
    "tenant_id": "<TENANT_ID>",
    "client_id": "<CLIENT_ID>",
    "resource_uri": "https://cognitiveservices.azure.com/"
  }
}'

warden policy write azure-openai-invoke - <<EOF
path "azure-openai/role/+/gateway/my-resource.openai.azure.com/openai/*" {
  capabilities = ["create", "update"]
}
EOF

warden role create azure-openai-user -json '{
  "policies": ["azure-openai-invoke"],
  "cred_spec_name": "azure-openai-invoke",
  "provider_path": "azure-openai/"
}'

warden identity group create azure-openai-user-agents -json '{
  "type": "virtual",
  "roles": ["azure-openai-user"],
  "rules": [
    { "mount": ["auth/jwt/"] }
  ]
}'

curl "${WARDEN_ADDR}/v1/azure-openai/role/azure-openai-user/gateway/my-resource.openai.azure.com/openai/v1/chat/completions" \
    -H "Authorization: Bearer ${JWT}" \
    -H "Content-Type: application/json" \
    -d '{
      "model": "gpt-4.1-mini",
      "messages": [
        { "role": "user", "content": "Say hi" }
      ]
    }'
```

The app registration named by `client_id` needs the `Cognitive Services OpenAI User` role
on the resource, and a federated credential for Warden's issuer, as on the
[Azure page](/provider-backends/azure/#3a-keyless-federation-recommended). On the `v1`
API the deployment is named by the body's `model` field, which a path policy does not
see. The `/openai/deployments/<deployment>/...` form puts it in the path, where a policy
can match it.
:::

## Quirks

- **A dedicated mount per model API.** A model call runs far longer than an ordinary API
  call, and it wants its own policy. Mount a provider for the model API alone, as above,
  rather than raising the timeout of the mount that serves the rest of the cloud.
- **`timeout` bounds the whole call.** A mount's `timeout` bounds the wait for the
  response headers, and a call that is not streamed sends its headers only when generation
  ends. It also bounds a streamed call from start to end. Set it to `300s` or more on a
  model mount. A `timeout` of `0` is refused; a call that runs past it is answered `504`.
- **`max_body_size` for large prompts.** The default is 10 MB and the limit is 100 MB. A
  request with images, documents or a long context can need more, and a request over the
  limit is refused.
- **High availability.** A call that reaches a standby node is forwarded to the active
  node, bounded by `forwarding_timeout` (default `1m`). Set it to at least the model
  mount's `timeout`; see [High-availability tuning](/configuration/#high-availability-tuning).
- **A policy per cloud that limits the model.** On Bedrock and Vertex AI the model id is
  in the path, so a path policy can allow one model and refuse the rest:
  `bedrock/gateway/model/<model-id>/*` and
  `vertex/role/+/gateway/<host>/.../models/<model-id>:*`. On Azure OpenAI, use the
  deployments form of the path. An inference-profile ARN carries `/`, so match it with `*`
  rather than `+`.
- **Hosts stay on the cloud.** The `aws` provider forwards only to an AWS host, whatever
  region or service the client signs. The `gcp` and `azure` providers forward only to a
  host under the mount's `allowed_host_suffixes`, and refuse any other with `403` before a
  token is added.

## See also

- [Keyless credentials](/federation/keyless-credentials/): the trust setup on each cloud.
- [AWS](/provider-backends/aws/), [GCP](/provider-backends/gcp/) and
  [Azure](/provider-backends/azure/): the full provider guides.
- [Policies](/identity/policies/): path rules and capabilities.
