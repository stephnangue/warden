---
title: "Claude Code agents that act for people, on Agent Substrate"
description: "Each person gets their own Claude Code agent on Agent Substrate. The agent holds no credential, does real work on GitHub and Kubernetes for its person, and Warden checks on every call which agent is calling, for whom, and what that person allows."
publishDate: 2026-11-11
tags: [agent-substrate, delegation, mcp, github, kubernetes]
heroImage: /images/blog/warden-blog-claude-code-agents-act-for-people-overview.png
---

[Agent Substrate](https://ate.dev/docs/) runs agents as sandboxed *actors* on
Kubernetes, can suspend one to a snapshot while it is idle, and resumes it in under a
second when a request arrives. An actor need hold no credential: when it calls out,
Substrate's egress gateway can attach a short-lived **actor JWT** that names it. That answers *which agent* is calling.

Most agents do not work for themselves, though. A coding agent opens pull requests for a
developer; an operations agent changes a cluster for an on-call engineer. Each of those
calls has two identities behind it, the agent and the person, and the person's own
permissions are the ones that should count. This post wires Warden behind Substrate so
that every call is checked for three things: which agent is calling, which person it
acts for, and what that person allows. The person's token never reaches the agent.

## Two people, two agents, real work

Alice and Bob each get their own Claude Code agent, an actor named `claude-alice` and
one named `claude-bob`. Each prompt carries the person's token. `ask` is a small shell
helper from the example: it sends the prompt through `kubectl ate proxy`, which resumes
the actor, and suspends the actor once the answer is back.

```bash
ask claude-alice "Create a new private GitHub repository named alice-agent-hello, …
  add a small Node.js command-line tool with a test, … push the branch, and open a
  pull request into main." as "$ALICE_TOKEN"

ask claude-bob "My web app in my Kubernetes namespace is down. Find out why and fix
  it, then confirm the pods are running." as "$BOB_TOKEN"
```

Alice's agent created a private repository, cloned it, wrote the tool and its tests, ran
them, pushed a branch and opened a pull request, in about 30 seconds. Bob's agent read
his pods' logs, found that the Deployment pointed nginx at a config file that does not
exist, patched it, and waited for the rollout, in about 40. Neither agent ever held a
GitHub token, a Kubernetes token or the person's token.

<p align="center"><img alt="Alice and Bob each send a prompt with their own JWT to their own Claude Code agent, an actor in a gVisor sandbox on Agent Substrate. In each actor, a root agent server holds the person's JWT and Claude Code runs as another user with no credential. Their calls leave through Substrate's egress gateway, which adds the actor JWT: calls for a person go to warden-on-behalf with the person's JWT in Authorization and the actor JWT in X-Warden-Agent-Token, and the agent's own calls go to warden with the actor JWT in Authorization. Warden adds a GitHub token for Alice's GitHub MCP and git calls, a 15-minute ServiceAccount token for Bob's Kubernetes calls, and an API key for the model, and forwards each call." src="/images/blog/warden-blog-claude-code-agents-act-for-people-overview.png" width="860"></p>

In the demo, `ask` plays the client app.

## Two identities on every call

**The agent** is the actor JWT. Substrate's issuer publishes an OpenID discovery
document, so Warden trusts it with an ordinary [JWT auth mount](/auth-methods/jwt/):

```bash
jq -n --rawfile ca substrate-idp-ca.pem '{
  "oidc_discovery_url": "https://idp.ate-system.svc",
  "oidc_discovery_ca_pem": $ca,
  "bound_issuer": "https://idp.ate-system.svc",
  "bound_audiences": ["warden"],
  "facts": {
    "/actor.ate.dev/atespace": "atespace"
  }
}' | warden write auth/substrate/config
```

The token's `sub`, `actor/<atespace>/<name>`, becomes the agent's principal, and a
[group](/identity/groups/) grants each agent its roles by that name. The `facts` line
makes the atespace available to conditions as `agent.metadata.atespace`; this demo
grants roles by actor name instead.

**The person** is their own token, issued by their identity provider with a `may_act`
claim that names the one agent allowed to act for them. A Warden provider with a user leg
(`user_auth_path`) reads both identities from the same request: the agent from
`X-Warden-Agent-Token`, the person from `Authorization`.

In the demo, the person's identity provider is the Warden playground's, and its mount
`auth/user/` publishes the claim as a fact, `"facts": {"/may_act/sub": "may_act_sub"}`,
which conditions read as `user.metadata.may_act_sub`:

```bash
ALICE_TOKEN=$(warden dev jwt user alice -may-act actor/claude-agents/claude-alice)
```

A mount for your own identity provider needs the same `facts` line, with
`"entity_kind": "human"` and its own `bound_audiences`.

Substrate's egress gateway fills a header only when the request already carries it, and
its rules apply per destination host. So Warden gets a second Service name: calls the
agent makes as itself go to `warden`, with the actor JWT in `Authorization`; calls it
makes for a person go to `warden-on-behalf`, where the actor JWT goes into
`X-Warden-Agent-Token` and `Authorization` passes through untouched.

```yaml
rules:
- http:
    hostnames: ["warden.warden.svc.cluster.local"]
    ports: {numbers: [8400]}
    effects:
      replaceHeaders:
      - header: Authorization
        prefix: "Bearer "
        actorJwt: {audiences: ["warden"], expirationSeconds: 900}
- http:
    hostnames: ["warden-on-behalf.warden.svc.cluster.local"]
    ports: {numbers: [8400]}
    effects:
      replaceHeaders:
      - header: X-Warden-Agent-Token
        actorJwt: {audiences: ["warden"], expirationSeconds: 900}
```

## The agent asks Warden what it may do

Neither agent is told which tools to use. The image registers Warden's
[discovery server](/concepts/discovery-and-skills/) as an MCP server named `warden`, on the `warden`
host, so it carries the agent's own actor JWT and no person's token. Claude Code's
`CLAUDE.md` says only where to start: call `list_roles`, pick the role that fits the
task, read its skill with `read_skill`, follow it, and report a refusal rather than work
around it.

`list_roles` answers with the roles the agent's group grants, each with the operator's
description and a skill. Warden's built-in skills tell an agent to call the role's URL
with its own token, which is wrong here: the agent holds none, and goes through a local
gateway (below). So each role points at a custom skill that says how it is reached from
the sandbox:

```bash
warden skill create sandbox-kubernetes -category=custom \
  -description="Use kubectl in the namespace of the person you act for, from an Agent Substrate sandbox, through its local gateway." \
  -body-file=skills/sandbox-kubernetes.md

warden role create kube-ops -json '{
  "description": "The Kubernetes API for the person this agent acts for, in their own namespace only.",
  "policies": ["bob-kube-ops"],
  "cred_spec_name": "bob-k8s",
  "provider_path": "k8s-actor/",
  "skill": "sandbox-kubernetes"
}'
```

```markdown
`kubectl` is already configured to reach the cluster through the local gateway: do not
set a server or a token, and do not call the role's `url`. Always name the namespace;
it has the person's name: `kubectl -n <person> …`.
```

Asked to name what it used, Bob's agent answered `kube-ops`, with
`skill://sandbox-kubernetes/SKILL.md`; Alice's named `github-tools` and `github-git` with
their skills. The skills describe the sandbox, not the rules: no naming rule, repository
or namespace limit is written there or in `CLAUDE.md`. Those live in Warden's policies.

## Policies that bind the person, the agent and the work

Every path an agent uses for a person carries the same condition: the person named this
very agent in `may_act`, and the person is the one this work belongs to.

```hcl
path "k8s-actor/role/+/gateway/api/v1/namespaces/bob/*" {
  capabilities = ["read", "list", "create", "update", "patch", "delete"]
  condition    = "user.present && user.metadata.may_act_sub == agent.principal && user.principal == 'bob'"
}
```

Bob's agent reaches the Kubernetes API through Warden's
[Kubernetes provider](/provider-backends/kubernetes/), which mints a 15-minute token for
a ServiceAccount with a narrow role in `bob`: read the app's pods, logs and events,
change its Deployments and ConfigMaps, run short-lived pods. The namespace enforces Pod
Security's `baseline` level, so none of those pods can be privileged or mount the node.
kubectl sends its edits as HTTP `PATCH`, which needs the `patch` capability.

Alice's agent reaches GitHub two ways: [GitHub's MCP server](/provider-backends/mcp-github/)
for the API, and Warden's [GitHub provider](/provider-backends/github/) for git. The MCP
mount carries the same binding:

```hcl
path "github-mcp-actor/role/+/gateway*" {
  capabilities = ["read", "create", "update", "delete", "list"]
  condition    = "user.present && user.metadata.may_act_sub == agent.principal && user.principal == 'alice'"
}
```

A second policy, of type `mcp` (`warden policy write -type mcp`), decides which tools the
agent sees and how it may call them. Warden reads each tool call's arguments, so the
policy can say *how* a tool may be called, not only which tools exist:

```hcl
path "github-mcp-actor/role/+/gateway*" {
  methods { allowed = ["tools/list", "tools/call", "subscriptions/listen", "prompts/list"] }
  tools   { allowed = ["get_me", "create_repository", "get_file_contents", "list_branches", "create_pull_request", "pull_request_read"] }
  condition = "call.method != 'tools/call' || call.tool == 'get_me' || (call.tool == 'create_repository' && has(call.args.name) && call.args.name.matches('^alice-agent-[A-Za-z0-9._-]+$') && has(call.args.private) && call.args.private == true && !has(call.args.organization)) || (call.tool in ['get_file_contents', 'list_branches', 'create_pull_request', 'pull_request_read'] && has(call.args.owner) && call.args.owner == 'stephnangue' && has(call.args.repo) && call.args.repo.matches('^alice-agent-[A-Za-z0-9._-]+$'))"
}
```

A repository may be created only private, in Alice's account, with a name of the form
`alice-agent-*`, and every other call must name one of those repositories. (In the demo,
Alice's GitHub account is the author's, `stephnangue`.) Each tool gets its own branch, so
a tool the condition does not name is refused, and repository names are matched whole,
with no slash, so none can carry a `..` toward another repository. No delete tool is in the
list, so the agent is never offered one. Git gets a path policy to match,
`github-actor/role/+/gateway/<owner>/alice-agent-*`.

The GitHub token behind this is broad: a fine-grained token over all repositories, with
the Administration permission so the agent can create repositories. That is the point of
the demo. The token could delete any repository; the agent can only create private
`alice-agent-*` ones and work in them, because Warden decides what the token is used for.

## Keeping the person's token out of the agent

The person's token has to reach Warden with each of the agent's calls, but the agent
should not be able to read it, copy it, or use it after the work is done. Alice's token
comes in with the prompt (1) and leaves the sandbox only through the local gateway (7),
on a call the egress gateway completes with the actor JWT (8). Claude Code's own calls to
the model go out as the agent alone (3, 4).

<p align="center"><img alt="Inside the actor claude-alice, a root agent server receives the prompt with Alice's JWT and starts Claude Code as another user. Claude Code's model calls go to the warden host with a placeholder in Authorization, which the egress gateway replaces with the actor JWT before Warden adds the Anthropic API key. Its git and GitHub MCP calls go, with no credential, to a local gateway inside the agent server on 127.0.0.1:8081, which routes them to github-actor or github-mcp-actor on warden-on-behalf with Alice's JWT in Authorization and a placeholder in X-Warden-Agent-Token. The egress gateway replaces the placeholder with the actor JWT, and Warden adds the GitHub token before calling GitHub's MCP server or github.com." src="/images/blog/warden-blog-claude-code-agents-act-for-people-actor-flow.svg" width="860"></p>

Four mechanisms, all inside the actor's image:

- **A gateway holds the token.** The agent's server, running as root, receives the token
  with the prompt and uses it for that run only. Claude Code's tools point at
  a local gateway on `127.0.0.1` with no credential: git's remote, kubectl's server and
  the MCP server's URL. The gateway adds the person's token and the agent-token
  placeholder, and forwards to three fixed routes on `warden-on-behalf`. It refuses paths
  with `..` segments, drops any `X-Warden-*` header the agent sets, answers nothing
  between runs, and cuts the calls still open when a run ends. It also makes kubectl
  work at all: kubectl cannot add a custom header. (Warden does not rely on the `..`
  check: it redirects a literal dot segment to the clean path, so policies see only
  that, and refuses an encoded one.)
- **Claude Code runs as another user.** The server is root and Claude Code is an
  unprivileged user, so `/proc` refuses Claude Code the server's memory and environment.
- **Each run gets a fresh home.** It is copied from a read-only template and deleted
  afterwards, so one person's working copy, files or session history never reach the
  next person's run.
- **Nothing keeps running.** When Claude Code exits, the server stops every process the
  agent user left behind. A background process could otherwise sit there and call the
  gateway during the next run, with the next person's token. The server then checks that
  no process and no file of that user is left; if one is, the agent refuses every
  prompt after it until it is recreated.

We checked it rather than trusting the design. With Bob's token loaded exactly as for a
prompt, a fixed script ran as the agent user and looked for the token everywhere Claude
Code could (output condensed):

```
uid=1000(node) gid=1000(node) groups=1000(node)
--- environment entries holding eyJ: 0
--- files under ~, /tmp, /var/tmp, /run/lock, /dev/shm, /opt holding eyJ:
  (end)
--- files of the agent user left by earlier runs:
  (end)
--- the template home: read-only
--- the server's /proc/2/environ:
cat: /proc/2/environ: Permission denied
--- the server's /proc/2/mem:
dd: failed to open '/proc/2/mem': Permission denied
--- dot-segment path through the gateway:
path not allowed
--- a role header through the gateway (kube-ops still answers):
"gitVersion": "v1.37.0"
--- the gateway works meanwhile:
Username    system:serviceaccount:bob:bob-agent
```

A JWT starts with `eyJ`, and none was within the agent's reach. The run before it had
been told to leave read-only folders, a background process and a loop that keeps
starting new ones behind; nothing survived, and the template stayed read-only. An `X-Warden-Role` header asking for
Alice's GitHub role changed nothing. Meanwhile the gateway was using Bob's token:
Kubernetes saw his agent's ServiceAccount.

This does not stop the agent from *acting* as the person while the run lasts, through the
gateway. That is what delegation means, and Warden's policies decide what that authority
covers.

## Watch it refuse

| What was asked | What stopped it |
|---|---|
| Alice's agent: create a **public** repository | Warden, on the tool's `private` argument |
| Alice's agent: create a repository named `demo-tools` | Warden, on the name |
| Alice's agent: clone another of her repositories | Warden, on the git path |
| Alice's agent: read `alice-agent-hello/../warden` | Warden, on the tool's `repo` argument |
| Alice's agent: delete a repository | The tool is not offered |
| Bob's agent: run a privileged pod that mounts the node | Kubernetes: Pod Security `baseline` |
| Alice's agent, with **Bob's** token | Warden: the wrong person, for an agent Bob did not name |
| Bob's agent, with **Alice's** token | Warden: the wrong person, for an agent Alice did not name |

GitHub never saw the refused calls: neither forbidden repository exists afterwards. The
agents reported each refusal and did not look for a way around it. Warden's audit names
both parties and the condition that failed (its Reason column, shown alone):

```bash
warden dev audit -principal actor/claude-agents/claude-bob -user alice -decision deny -limit 1
```

```
reason: condition: user.present && user.metadata.may_act_sub == agent.principal && user.principal == 'bob'
```

## What bit us

- **Starting Claude Code as another user needs `SETUID` and `SETGID`.** Substrate gives a
  container only `AUDIT_WRITE`, `KILL` and `NET_BIND_SERVICE`; the actor template adds
  the two.
- **Root in the sandbox has no `DAC_OVERRIDE`.** Node enters a child process's working
  directory *before* it drops privileges, so starting Claude Code in a home only its user
  can enter failed with `EACCES`. The `cd` now happens after the switch, in `sh -c`.
- **A background process kept a run from finishing.** It held the output pipe open.
  Stopping the agent user's processes as soon as Claude Code exits fixes both the hang
  and the cross-run risk.
- **The first version leaked between runs.** It kept one working folder per agent, and a
  prompt sent with the wrong person's token answered from the previous run's clone,
  without calling Warden. Hence the fresh home per run.
- **The rules belong in Warden, not in the prompt.** With the naming rules written into
  Claude Code's `CLAUDE.md`, the agent enforced them itself and the policy never got to
  refuse anything. `CLAUDE.md` now describes the environment only.
- **A prefix check is not a name check.** The first MCP policy accepted any repository
  whose name *started* with `alice-agent-`, so `alice-agent-x/../other-repo` passed it.
  Whether that reaches another repository depends on how the MCP server turns arguments
  into GitHub API URLs, which Warden cannot see. The policy now matches the whole name.
- **A namespace role is not a namespace boundary.** Bob's ServiceAccount first had the
  built-in `edit` role in `bob`. That lets it create any pod there, including a
  privileged one that mounts the node's filesystem, which leaves the namespace behind.
  Pod Security's `baseline` level and a narrower role close that.
- **Cleaning up after a run has to check its work.** A run that left a read-only folder
  in `/tmp` defeated the first cleanup. The server now makes the folders writable before
  deleting, and refuses further prompts if anything remains.

## Before production

- **Route each person to their own agent.** The agent server does not verify the
  person's token; Warden does, on every call. The application in front of Substrate's
  ingress has to send a person's prompts to that person's agent only, and should be the
  only client Substrate's ingress admits (`--ingress-allowed-spiffe-ids` at install).
- **The person's token is in the sandbox for the length of a run.** The server drops it
  afterwards, but a dropped string can stay in the process heap until it is overwritten,
  and so in the snapshot taken when the actor is suspended. Keep the token short-lived,
  issued for Warden's audience, and bound by `may_act` to one agent.
- **Stop storing credentials in Warden.** The demo stores the GitHub token, the model API
  key and a Kubernetes source token, the quickest start. In production, keep them in your
  secret store and let Warden fetch them per request with
  [credential chaining](/federation/credential-chaining/).
- **TLS to Warden.** Calls from Substrate's egress gateway to Warden are plain HTTP inside
  the cluster here. In v1.0.0, the egress gateway checks an upstream's certificate
  against the public roots in its Envoy image, with no setting for a private CA; Substrate
  tracks one in [#3648](https://github.com/agent-substrate/substrate/issues/3648). Until
  then, Warden needs a name under a domain you own, resolvable inside the cluster, with a
  publicly trusted certificate: no public CA signs for `.svc.cluster.local`. The two
  egress rules then become `https` rules, so the image must trust Substrate's egress CA,
  which it gets from a [trust-bundle volume](https://ate.dev/docs/guides/egress-trust-bundle/),
  and the agent server, `ANTHROPIC_BASE_URL` and the `warden` MCP server switch to
  `https`.
- **No `kubectl exec`, `port-forward` or `attach`.** They need an upgraded connection,
  which Substrate's egress gateway refuses. Bob's agent works through pod status, logs
  and short-lived pods instead.

> **In production, register the agent.** This demo grants roles with virtual groups,
> which match whatever actor carries the name. Register each agent as an
> [entity](/identity/entities/) with a sponsor and a static group, and set
> `governed_only` on its roles, so an agent nobody claimed gets nothing.

## Try it

The full walkthrough runs on a laptop, in a kind cluster: Substrate, the Warden
playground, both agents, the self-check, every file and every command. It needs Docker
with buildx and 4 CPUs and 6 GiB for its VM, Go, kubectl, git, jq, the Warden CLI, an
Anthropic API key, and a GitHub account for Alice's part.

```bash
git clone https://github.com/stephnangue/warden-tuto.git
cd warden-tuto/access-delegation-agent-substrate
```

Verified with Agent Substrate v1.0.0, Warden v0.22.0, Claude Code 2.1.322 and Kubernetes
v1.37.0. The [example](https://github.com/stephnangue/warden-tuto/tree/main/access-delegation-agent-substrate)
has the agent's server, the image, the policies and the manifests.
