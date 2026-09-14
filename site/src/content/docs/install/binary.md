---
title: "Install the Warden Binary"
description: "Install the warden binary on macOS, Linux, or Windows — install script, release archives, checksum verification, upgrades, and building from source."
sidebar:
  label: Binary
  order: 2
---

Warden is a single static binary named `warden`, with no runtime dependencies.
The same binary is the command-line client and the server (`warden server`) —
installing it once gives you both.

Prebuilt archives are published for **linux/amd64**, **linux/arm64**,
**darwin/amd64**, **darwin/arm64**, and **windows/amd64**.

- [macOS](#macos)
- [Linux](#linux)
- [Windows](#windows)
- [Verify the download](#verify-the-download)
- [Verify the install](#verify-the-install)
- [Upgrading](#upgrading)
- [Uninstalling](#uninstalling)
- [Building from source](#building-from-source)

:::note[How release assets are named]
Archives are named `warden_<version>_<os>_<arch>.tar.gz` — the version in the
filename has **no** leading `v`, while the release tag in the URL **does**. For
`v0.20.0` on Apple Silicon that is
`warden_0.20.0_darwin_arm64.tar.gz`, downloaded from
`.../releases/download/v0.20.0/`. Windows archives are `.zip`, not `.tar.gz`.

The commands below resolve the version rather than hardcoding it, so they stay
correct as releases land.
:::

---

## macOS

### Install script (recommended)

```bash
curl -sL https://wardengateway.com/install.sh | bash
```

The script detects your architecture and installs into the first of
`~/.local/bin`, `/opt/homebrew/bin`, `/usr/local/bin`, `~/bin` that exists, is
writable, and is already on your `PATH`, falling back to `~/.local/bin` when
none qualifies. It does not consider any other directory, even one on your
`PATH` — pick the destination yourself with `WARDEN_INSTALL_DIR`:

```bash
curl -sL https://wardengateway.com/install.sh | WARDEN_INSTALL_DIR="$HOME/bin" bash
```

If the destination is not already on your `PATH`, the script appends an
`export PATH=...` line — marked `# Added by the Warden installer` — to your
`~/.zshrc`, `~/.bashrc`, or `~/.profile`, and prints the path it chose.

Read it first if you would rather not pipe an unread script to a shell:

```bash
curl -sL https://wardengateway.com/install.sh | less
```

### Manual download

Apple Silicon (arm64):

```bash
VERSION=$(curl -fsSL https://api.github.com/repos/stephnangue/warden/releases/latest \
  | grep '"tag_name"' | cut -d'"' -f4)          # e.g. v0.20.0

curl -fsSLO "https://github.com/stephnangue/warden/releases/download/${VERSION}/warden_${VERSION#v}_darwin_arm64.tar.gz"
tar -xzf "warden_${VERSION#v}_darwin_arm64.tar.gz" warden
sudo install -m 0755 warden /usr/local/bin/warden
```

Intel (amd64):

```bash
VERSION=$(curl -fsSL https://api.github.com/repos/stephnangue/warden/releases/latest \
  | grep '"tag_name"' | cut -d'"' -f4)

curl -fsSLO "https://github.com/stephnangue/warden/releases/download/${VERSION}/warden_${VERSION#v}_darwin_amd64.tar.gz"
tar -xzf "warden_${VERSION#v}_darwin_amd64.tar.gz" warden
sudo install -m 0755 warden /usr/local/bin/warden
```

### If Gatekeeper blocks the binary

Release binaries are not code-signed or notarized. Gatekeeper only quarantines
files downloaded by a browser — `curl` does not set the quarantine attribute, so
the commands above are unaffected. If you did download the archive through a
browser and macOS refuses to run the binary:

```bash
xattr -d com.apple.quarantine /usr/local/bin/warden
```

---

## Linux

### Install script (recommended)

```bash
curl -sL https://wardengateway.com/install.sh | bash
```

:::tip[Installing system-wide]
The script never uses `sudo` on its own. For a root-owned install, run it under
`sudo` and pass the destination explicitly:

```bash
curl -sL https://wardengateway.com/install.sh | sudo WARDEN_INSTALL_DIR=/usr/local/bin bash
```
:::

### Manual download

amd64:

```bash
VERSION=$(curl -fsSL https://api.github.com/repos/stephnangue/warden/releases/latest \
  | grep '"tag_name"' | cut -d'"' -f4)          # e.g. v0.20.0

curl -fsSLO "https://github.com/stephnangue/warden/releases/download/${VERSION}/warden_${VERSION#v}_linux_amd64.tar.gz"
tar -xzf "warden_${VERSION#v}_linux_amd64.tar.gz" warden
sudo install -m 0755 warden /usr/local/bin/warden
```

arm64:

```bash
VERSION=$(curl -fsSL https://api.github.com/repos/stephnangue/warden/releases/latest \
  | grep '"tag_name"' | cut -d'"' -f4)

curl -fsSLO "https://github.com/stephnangue/warden/releases/download/${VERSION}/warden_${VERSION#v}_linux_arm64.tar.gz"
tar -xzf "warden_${VERSION#v}_linux_arm64.tar.gz" warden
sudo install -m 0755 warden /usr/local/bin/warden
```

---

## Windows

### Download and extract

Windows archives are `.zip`. In PowerShell:

```powershell
$Version = (Invoke-RestMethod https://api.github.com/repos/stephnangue/warden/releases/latest).tag_name
$Asset   = "warden_$($Version.TrimStart('v'))_windows_amd64.zip"

Invoke-WebRequest "https://github.com/stephnangue/warden/releases/download/$Version/$Asset" -OutFile $Asset
Expand-Archive $Asset -DestinationPath "$env:LOCALAPPDATA\Warden" -Force
```

### Add warden to PATH

```powershell
[Environment]::SetEnvironmentVariable(
  "Path",
  [Environment]::GetEnvironmentVariable("Path", "User") + ";$env:LOCALAPPDATA\Warden",
  "User")
```

Open a new terminal, then:

```powershell
warden --version
```

:::caution[Windows on ARM is not published]
Release archives cover windows/amd64 only. On an ARM64 Windows machine, run the
amd64 binary under emulation, use WSL2 and follow the [Linux](#linux)
instructions, or [build from source](#building-from-source).

The install script is bash and covers macOS and Linux only. Under WSL2 it works
normally.
:::

---

## Verify the download

Every release publishes a single `checksums.txt` covering all archives.

```bash
VERSION=$(curl -fsSL https://api.github.com/repos/stephnangue/warden/releases/latest \
  | grep '"tag_name"' | cut -d'"' -f4)
curl -fsSLO "https://github.com/stephnangue/warden/releases/download/${VERSION}/checksums.txt"
```

Linux:

```bash
sha256sum --ignore-missing -c checksums.txt
```

macOS:

```bash
shasum -a 256 --ignore-missing -c checksums.txt
```

Windows — self-contained, so it does not depend on the earlier download block:

```powershell
$Version = (Invoke-RestMethod https://api.github.com/repos/stephnangue/warden/releases/latest).tag_name
$Asset   = "warden_$($Version.TrimStart('v'))_windows_amd64.zip"

Invoke-WebRequest "https://github.com/stephnangue/warden/releases/download/$Version/checksums.txt" `
  -OutFile checksums.txt

$Expected = (Select-String -Path checksums.txt -Pattern $Asset).Line.Split(' ')[0]
$Actual   = (Get-FileHash $Asset -Algorithm SHA256).Hash.ToLower()
if ($Expected -ne $Actual) { throw "checksum mismatch" } else { "OK" }
```

`checksums.txt` is not signed. It establishes that the archive you downloaded is
the one attached to the GitHub Release — integrity, not provenance.

---

## Verify the install

```bash
warden --version
warden --help
```

A quick end-to-end smoke test, which needs no configuration and writes nothing to
disk:

```bash
warden server -dev -dev-root-token=root
```

Leave it running and, in a second terminal:

```bash
export WARDEN_ADDR='http://127.0.0.1:8400'
export WARDEN_TOKEN='root'
warden status
```

Stop the server with `Ctrl-C`. See [Dev Server](/concepts/dev-server/) for what
dev mode does and does not provide.

---

## Upgrading

Re-running the install script overwrites the binary in place:

```bash
curl -sL https://wardengateway.com/install.sh | bash
warden --version
```

The client and the server are the same binary, so this upgrades both. Before
upgrading a server binary that fronts an existing PostgreSQL store, check the
upgrade guide for the version you are moving to — for example
[from v0.19](/upgrade/from-v0-19/) — since some releases change configuration or
policy syntax.

---

## Uninstalling

macOS and Linux:

```bash
rm -f "$(command -v warden)"
```

If the install script added a directory to your `PATH` and you no longer want it,
remove the line marked `# Added by the Warden installer` — and the comment above
it — from `~/.zshrc`, `~/.bashrc`, or `~/.profile`.

Windows:

```powershell
Remove-Item -Recurse "$env:LOCALAPPDATA\Warden"

# Drop the PATH entry added during install.
$Path = [Environment]::GetEnvironmentVariable("Path", "User")
$Kept = ($Path -split ';' | Where-Object { $_ -ne "$env:LOCALAPPDATA\Warden" }) -join ';'
[Environment]::SetEnvironmentVariable("Path", $Kept, "User")
```

Warden writes no dotfiles, no configuration directory, and no token cache. The
binary and that `PATH` entry are all there is to remove.

---

## Building from source

Building requires Go 1.26.7 or newer.

```bash
go install github.com/stephnangue/warden@latest
```

:::caution[A source build reports its version as `dev`]
The version string is stamped at link time by the release pipeline
(`-ldflags "-X main.version=..."`), not by the compiler. A binary produced by
`go install` therefore reports:

```
warden version dev
```

That is cosmetic on a laptop and misleading anywhere you need to know which
build you are running.

`go install pkg@version` does not accept `-ldflags`, so to get a stamped build,
clone and pass it yourself:

```bash
git clone --depth 1 --branch v0.20.0 https://github.com/stephnangue/warden
cd warden
go build -ldflags "-s -w -X main.version=0.20.0" -o warden .
```
:::

---

## Next steps

- [Dev Server](/concepts/dev-server/) — the flags, the output, and its limits
- [Quickstarts](/quickstarts/workstation/) — put an agent behind Warden
- [Configuration](/configuration/) — the HCL a real server needs
- [CLI reference](/cli/)
