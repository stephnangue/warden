---
title: "Local dev setup"
---

Every provider guide assumes you have a local Warden environment running. This
page sets one up once — an identity provider ([Ory Hydra](https://www.ory.sh/hydra/))
to issue the JWTs used for authentication, plus a Warden server in dev mode.
Follow it before **Step 1** of any provider guide, then return to the provider
you're configuring.

:::note
Dev mode uses in-memory storage — all configuration is lost when the server
stops. It is for local evaluation only, not production.
:::

## 1. Deploy the quickstart stack

This starts Ory Hydra, which issues the JWTs the provider guides authenticate in
their Step 1 and Step 5:

```bash
curl -fsSL -o docker-compose.quickstart.yml \
  https://raw.githubusercontent.com/stephnangue/warden/main/deploy/docker-compose.quickstart.yml
docker compose -f docker-compose.quickstart.yml up -d
```

## 2. Download the latest Warden binary

```bash
# macOS (Apple Silicon)
curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_darwin_arm64.tar.gz | tar xz

# macOS (Intel)
curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_darwin_amd64.tar.gz | tar xz

# Linux (x86_64)
curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_linux_amd64.tar.gz | tar xz

# Linux (ARM64)
curl -L https://github.com/stephnangue/warden/releases/latest/download/warden_$(curl -s https://api.github.com/repos/stephnangue/warden/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d v)_linux_arm64.tar.gz | tar xz
```

## 3. Add the binary to your PATH

```bash
export PATH="$PWD:$PATH"
```

## 4. Start the Warden server in dev mode

```bash
warden server -dev -dev-root-token=root
```

For TLS and mTLS dev-server options (needed for the certificate auth flow), see
[Serving TLS](/concepts/dev-server/#serving-tls).

## 5. Export the CLI environment variables

In another terminal window:

```bash
export PATH="$PWD:$PATH"
export WARDEN_ADDR="http://127.0.0.1:8400"
export WARDEN_TOKEN="root"
```

You now have a Warden server and an identity provider running locally. Continue
with **Step 1** of the provider guide you're following.

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since dev mode uses in-memory storage, all configuration is lost when the server
stops.
