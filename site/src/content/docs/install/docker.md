---
title: "Run Warden with Docker"
description: "Pull the Warden container image, run a dev server, mount an HCL config, and use the debug image variant."
sidebar:
  label: Docker
  order: 3
---

Every Warden release publishes a container image to the GitHub Container
Registry. It is the same binary as the release archive, on a distroless base —
useful for a throwaway server, for a Compose stack that already has the rest of
your dependencies, or as the starting point for a deployment you build yourself.

- [The image](#the-image)
- [Pull](#pull)
- [Dev mode in a container](#dev-mode-in-a-container)
- [Running with a config file](#running-with-a-config-file)
- [Docker Compose](#docker-compose)
- [The debug image](#the-debug-image)
- [File ownership and read-only filesystems](#file-ownership-and-read-only-filesystems)

---

## The image

| | |
|---|---|
| Repository | `ghcr.io/stephnangue/warden` (public — no `docker login` needed) |
| Release tag | `v<version>` — **with a leading `v`**, e.g. `v0.21.0` |
| Moving tags | `latest`, `debug` |
| Debug variant | `v<version>-debug` |
| Base | `gcr.io/distroless/static-debian12:nonroot` — no shell, no package manager, no DNS tools |
| User | `nonroot`, **UID/GID 65532** |
| Entrypoint | `["./warden", "server"]` |
| Default command | `["--config", "/config/warden.hcl"]` |
| Exposed port | `8400` (API). Inter-node forwarding uses `8401`; publish it yourself if you run a multi-node cluster. |
| Platforms | linux/amd64, linux/arm64 |

:::note[The entrypoint already supplies `warden server`]
Anything you write after the image name replaces the image's *command*, not its
entrypoint — so you pass **flags, not subcommands**:

```bash
docker run ghcr.io/stephnangue/warden:latest -dev     # runs: ./warden server -dev
```

Writing `... warden server -dev` would run `./warden server warden server -dev`
and fail. The same applies to `command:` in a Compose file.
:::

:::note[Image tags carry a `v`, chart versions do not]
Four numbers travel together and only two of them match. For the v0.21.0
release: the git tag is `v0.21.0`, the image tag is `v0.21.0`, the release
archive is `warden_0.21.0_<os>_<arch>.tar.gz`, and the Helm chart version is an
unrelated number entirely. See
[Chart version vs Warden version](/install/helm/#chart-version-vs-warden-version).
:::

---

## Pull

```bash
docker pull ghcr.io/stephnangue/warden:v0.21.0   # pin this for anything persistent
docker pull ghcr.io/stephnangue/warden:latest    # fine for a throwaway
```

---

## Dev mode in a container

```bash
docker run --rm --name warden-dev -p 127.0.0.1:8400:8400 \
  ghcr.io/stephnangue/warden:latest -dev -dev-root-token=root
```

```bash
export WARDEN_ADDR='http://127.0.0.1:8400'
export WARDEN_TOKEN='root'
warden status
```

The image sets `WARDEN_DEV_LISTEN_ADDRESS=0.0.0.0:8400`, so dev mode listens on
every interface of the *container* — the published port reaches it, and so can
other containers on the same Docker network. To keep it on the container's
loopback, pass `-dev-listen-address=127.0.0.1:8400`.

:::caution
Dev mode serves plain HTTP with an in-memory barrier and a known root token.
Publish it on `127.0.0.1` as shown — `-p 127.0.0.1:8400:8400`. A bare
`-p 8400:8400` exposes the root-token listener to your whole network.
:::

To try Warden with an agent rather than a bare server, run the playground instead:
`-dev-playground` in place of `-dev`, then follow
[Getting started](/getting-started/).

### Dev mode with TLS

```bash
docker run --rm --name warden-dev -p 127.0.0.1:8400:8400 \
  -v warden-certs:/certs \
  ghcr.io/stephnangue/warden:latest \
  -dev -dev-root-token=root -dev-tls \
  -dev-tls-cert-dir=/certs -dev-tls-san=warden-dev
```

`-dev-tls` generates a self-signed certificate; `-dev-tls-cert-dir` writes it to a
directory you can read, and keeps it after shutdown. `/certs` ships in the image
owned by the container's user, so a new named volume mounted there needs no
`chown`. Add `-dev-tls-san` for each name clients reach the container by. To serve
your own certificate instead, mount it and pass `-dev-tls-cert-file` and
`-dev-tls-key-file`. See [Serving TLS](/concepts/dev-server/#serving-tls).

---

## Running with a config file

The image's default command is `--config /config/warden.hcl`, so mounting your
configuration at exactly that path needs no command override:

```bash
# 32 raw bytes for AES-256-GCM — not base64. Warden reads the file verbatim.
mkdir -p seal && openssl rand 32 > seal/key

docker run -d --name warden \
  -p 8400:8400 -p 8401:8401 \
  -v "$PWD/warden.hcl:/config/warden.hcl:ro" \
  -v "$PWD/certs:/certs:ro" \
  -v "$PWD/seal:/seal:ro" \
  -v warden-audit:/var/log/warden \
  ghcr.io/stephnangue/warden:v0.21.0
```

Every path the configuration names has to be mounted — `/certs` and `/seal`
above. See [File ownership](#file-ownership-and-read-only-filesystems) for who
must be able to read them.

:::caution[The listener must bind `0.0.0.0`]
A listener bound to `127.0.0.1` is reachable only from inside the container —
the same failure as dev mode above, but silent, because the server starts
normally. Sample configurations written for a binary running on the host bind
loopback; change the address when you move them into a container.
:::

A minimal container-shaped configuration:

```hcl
api_addr     = "https://warden.example.com:8400"
cluster_addr = "https://warden.example.com:8401"

listener "tcp" {
  address            = "0.0.0.0:8400"
  tls_cert_file      = "/certs/warden-cert.pem"
  tls_key_file       = "/certs/warden-key.pem"
  tls_client_ca_file = "/certs/ca.pem"
}

storage "postgres" {
  connection_url = "postgres://warden:PASSWORD@postgres:5432/warden?sslmode=require"
  ha_enabled     = "true"
}

seal "static" {
  current_key_id = "20260914-1"
  current_key    = "file:///seal/key"
}
```

Use `--config-dir /config` instead to merge every `.hcl` file in a directory in
lexical order.

The configuration supports `{{ env "VAR" }}` interpolation, so secrets belong in
`--env` or `--env-file` rather than baked into the mounted file:

```hcl
storage "postgres" {
  connection_url = "{{ env "WARDEN_POSTGRES_URL" }}"
  ha_enabled     = "true"
}
```

The first start comes up **uninitialized** — `/v1/sys/health` returns 501 and the
server serves nothing until an operator runs `warden operator init` once. See
[First-time initialization](/install/kubernetes/#first-time-initialization) for
the flow, and [Seal and unseal](/concepts/seal-unseal/) for what to do with the
keys it returns.

---

## Docker Compose

A minimal dev stack:

```yaml
name: warden-dev

services:
  warden:
    image: ghcr.io/stephnangue/warden:latest
    command: ["-dev", "-dev-root-token=root"]
    ports:
      - "127.0.0.1:8400:8400"
```

```bash
docker compose up -d

export WARDEN_ADDR='http://127.0.0.1:8400'
export WARDEN_TOKEN='root'
warden status

docker compose down
```

Other services in the stack reach it as `http://warden:8400`.

For a full stack with mTLS, a certificate-based agent identity, and an agent
actually talking through Warden, see the
[workstation quickstart](/quickstarts/workstation/01-cert-llm/).

---

## The debug image

The production image is distroless: no shell, no `ls`, nothing to exec into. Each
release also publishes a sibling built from the same binary on a base that
bundles a BusyBox shell, at the same repository with a `-debug` suffix (plus a
moving `debug` tag). UID, GID, entrypoint, and the `/config` contract are
identical, so swapping the tag changes nothing else.

```bash
docker run --rm --entrypoint sh \
  ghcr.io/stephnangue/warden:debug -c 'pwd; ls -l; id'
```

```
/app
-rwxr-xr-x 1 root root 65601698 warden
uid=65532(nonroot) gid=65532(nonroot) groups=65532(nonroot)
```

`--entrypoint sh` is required — the default entrypoint is `./warden server`. Add
`-it` for an interactive shell instead of `-c`.

`/config`, `/certs` and `/var/log/warden` ship empty in both images, ready to be
mounted over. Inspecting a *running* container is the usual case:

```bash
docker exec warden ls -l /config
```

The debug variant carries a larger attack surface by design. Use it for
short-lived diagnostic windows, not steady-state operation. For the in-cluster
equivalent, see
[Debugging inside the Warden container itself](/install/kubernetes/#debugging-inside-the-warden-container-itself).

---

## File ownership and read-only filesystems

**UID 65532.** The container runs as `nonroot:nonroot` — UID and GID 65532. Every
bind-mounted file has to be readable by that user. A TLS private key mounted
`0600 root:root` produces a startup failure that reads like a configuration
error:

```bash
sudo chown 65532:65532 ./certs/warden-key.pem
chmod 0600 ./certs/warden-key.pem
```

Docker Desktop on macOS and Windows remaps ownership inside its VM, so this only
bites on Linux.

**Writable paths.** The file audit device writes to the path in its `file_path`
option, and that directory has to be writable by 65532. The image ships
`/var/log/warden` and `/certs` owned by 65532, and a new **named volume** mounted
there takes that ownership — so `-v warden-audit:/var/log/warden` works with no
preparation. A **bind mount** keeps the host directory's ownership instead:
`sudo chown 65532:65532 ./audit` on the host, once.

**Read-only root filesystem.** Warden runs fine with `--read-only`, but the
distroless base has no writable `/tmp`:

```bash
docker run --read-only --tmpfs /tmp:rw,size=64m \
  --cap-drop ALL --security-opt no-new-privileges \
  -p 8400:8400 \
  -v "$PWD/warden.hcl:/config/warden.hcl:ro" \
  -v warden-audit:/var/log/warden \
  ghcr.io/stephnangue/warden:v0.21.0
```

`-dev-tls` without explicit certificate files needs a writable temporary
directory and fails under `--read-only` without that tmpfs.

---

## Next steps

- [Dev Server](/concepts/dev-server/) — flags, output, and limits
- [Configuration](/configuration/) — listener, storage, seal, audit
- [Kubernetes](/install/kubernetes/) — the production deployment
- [Quickstarts](/quickstarts/workstation/)
