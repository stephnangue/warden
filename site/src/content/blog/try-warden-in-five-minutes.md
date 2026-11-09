---
title: "Try Warden in five minutes"
description: "Warden v0.21.0 ships a playground: one container with its own identity provider and a bank to protect, and a nine-scenario tour you take from the agent you already use."
publishDate: 2026-10-05
tags: [release, playground, mcp, policy]
---

Until this release, the shortest path to watching Warden govern an agent ran through
an identity provider you had to stand up, an upstream key you had to find, and a
Compose stack to wire them together. It took the better part of an hour before the
first request was authorized — and most of that hour was spent on things that were
not Warden.

v0.21.0 removes that hour. One container starts Warden with everything it protects
already in place:

```bash
docker run --rm --name warden-playground -p 127.0.0.1:8400:8400 \
  ghcr.io/stephnangue/warden:latest -dev-playground -dev-root-token=root
```

Behind it run an identity provider that signs the agents' and users' tokens, and a
small bank — an MCP server and an HTTP API, with balances, withdrawals, and a
payment request someone has planted with a prompt injection. You then drive the bank
from the agent you already use: Claude Code, Codex, Cursor, Gemini CLI, opencode,
VS Code, or any MCP client. [Getting started](/getting-started/) writes the whole
tour out for each of them.

Three of its nine scenarios show something no configuration file can.

## Policy that reads the arguments

Scenario 3 asks the agent to withdraw 50, then 300. The first goes through. The
second is refused by Warden before the bank sees it, by one condition on the `atm`
role's MCP policy:

```
call.tool != 'withdraw' || (has(call.args.amount) && call.args.amount <= 100)
```

It runs on every MCP call, so it judges only `withdraw`, and it fails closed: a
withdrawal whose amount cannot be read is refused, not waved through. Then you raise
the limit to 400 — one `warden policy write` — and ask again. The same 300 goes
through on the next call. Nothing about the agent changed, nothing about the bank,
and nobody reconnected: the decision is made per call, against the policy as it is
at that moment.

## A memo cannot move the money

In scenario 5 the agent acts for a person, alice. It reaches the bank with two
tokens — its own, and alice's — so the bank debits alice's account, and the policy
applies alice's withdrawal limit: 100, since her token carries no premium tier. You
ask the agent to go through alice's recent transactions and take care of anything
that needs action. One of them is a payment request whose memo, written by a third
party, tells the agent to withdraw 900 and close the account.

What the agent makes of that memo is the model's judgement. It may spot the trick;
a better-written memo might not be spotted. The point of the scenario is that it
does not matter. If the agent obeys, Warden refuses the 900, because the limit is
read from alice's signed token, not from the conversation. `close_account` is not
even in the agent's tool list — the role's policy removed it. The optional "Insist"
step has you approve the memo yourself, in the chat, and the refusal stands: nothing
said in the conversation can raise a limit that comes from a signed claim.

That is a defence against prompt injection that does not depend on the model winning
an argument. The agent can be fooled. What it is *allowed* to do cannot be talked up.

## The agent finds its own way

In scenario 7 you connect the agent to Warden's discovery server. Asked what it can
do, the agent calls `list_roles` and gets each role it may assume, with a
description, the provider behind it, a skill to read, and the URL to call. In
scenario 8 you disconnect the agent from the bank's MCP server altogether and ask it
to use the bank's HTTP API. The agent finds the `teller` role, reads its skill, and
calls the API with its own token — and the withdrawal of 500 is refused by a
condition on the JSON body, again written to fail closed.

No one configured the agent for that. A new system is reachable the moment a role
grants it, without redistributing config to every agent that might need it.

## Your own service next

The last scenario puts GitHub's MCP server behind the same Warden. The playground
has already set it up like the bank — a role, and a policy that lets through only
GitHub's read-only tools. It lacks one thing, a credential, and you bring it: a
personal access token, read without echo and stored on a credential spec. Same agent,
same identity, same Warden — only the upstream changed. Creating that spec warns that
it stores a secret, which the bank's keyless token never did; in production, keep the
token in your own secret store and let Warden fetch it per request with
[credential chaining](/federation/credential-chaining/).

## The rest of v0.21.0

- **Discovery grows up.** Roles name their skill and provider in structured fields,
  agents read skills with `read_skill` or the MCP Skills extension, and what an agent
  can read is bound to who it is.
- **Keyless reaches further.** Anthropic and OpenAI federate, Cloudflare gets a
  keyless source, and Azure Key Vault joins the chaining producers.
- **Delegation in one token.** The default assertion is now an RFC 8693 delegation
  token: the user on top, the agent in `act`.
- **Failures in the upstream's own words.** When Warden refuses a request, AWS, OpenAI
  and Anthropic clients read the error in the shape they expect.

v0.21.0 carries nine breaking changes. The [release notes](https://github.com/stephnangue/warden/releases/tag/v0.21.0)
list them, and [Upgrading from v0.20.0](/upgrade/from-v0-20/) walks through each.
