#!/usr/bin/env bash
#
# Documentation invariants — patterns that must not reappear in the docs.
#
# Each entry below names syntax the server no longer accepts. A doc that teaches
# it is worse than a doc that omits it: the reader copies an example and the
# write is rejected, or worse, silently does nothing. These checks are cheap and
# they are the only thing standing between a rename and a slow drift back.
#
# Scope notes:
#   - site/src/content/docs/upgrade/ is EXCLUDED. Upgrade guides necessarily
#     quote the old world in their "before" examples.
#   - provider/*/skill.md is INCLUDED. Those files are go:embed'd into the
#     binary and served to agents at runtime, so stale syntax there ships
#     inside the release rather than merely on the website.
#
# Run from anywhere:  ./site/scripts/check-invariants.sh
# A non-zero exit lists every offending line.

set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

docs="site/src/content/docs"
skills=(provider/*/skill.md)

status=0

# check <label> <regex> <path>...
#
# Passes when the pattern is absent. grep exits 1 for "no match" (what we want)
# and 2 for a real error (a bad path, an unreadable file) — which must not be
# mistaken for success.
check() {
  local label="$1" pattern="$2"
  shift 2

  local out rc
  out="$(grep -rnE "$pattern" "$@" --exclude-dir=upgrade 2>&1)"
  rc=$?

  case "$rc" in
    0)
      printf '✗ %s\n' "$label"
      printf '%s\n' "$out" | sed 's/^/    /'
      printf '\n'
      status=1
      ;;
    1)
      printf '✓ %s\n' "$label"
      ;;
    *)
      printf '✗ %s — grep failed (exit %d)\n' "$label" "$rc"
      printf '%s\n' "$out" | sed 's/^/    /'
      status=1
      ;;
  esac
}

# The `token` CEL namespace was renamed to `agent` in v0.20.0 with no alias, so a
# condition naming it fails to compile. Matching the fields rather than a bare
# `token.` keeps prose like "the token's metadata" out of the results.
check "CEL namespace: no \`token.<field>\`" \
  '\btoken\.(principal|role|type|namespace|policies|metadata|actors|ttl_seconds|expires_at)\b' \
  "$docs"

# --- Pending checks -----------------------------------------------------------
#
# A check may only be enabled by the PR that removes the LAST occurrence of its
# pattern. Enabling one early fails every in-flight branch that does not happen
# to carry the fix, including branches whose own files are already clean — and
# when two such branches each hold part of the fix, neither can merge.
#
# Uncomment each block in the PR named beside it.

# Enable with the MCP policy-type sweep, which rewrites the four MCP provider
# pages, the tutorials and quickstarts, and the two embedded skills.
#
# check "MCP policy: no nested \`mcp {\` block" \
#   'mcp[[:space:]]*\{' \
#   "$docs" "${skills[@]}"

# Enable with the credential-drivers refresh, which deletes the honeycomb driver
# page and its sidebar slug. Scoped to the driver docs because the honeycomb
# *provider* still exists and keeps its page.
#
# check "Credential drivers: no honeycomb driver" \
#   'honeycomb' \
#   "$docs/credential-drivers" site/astro.config.mjs

# Enable with the provider mechanical pass, which renames optional_metadata and
# removes the retired IBM and OVH mint methods.
#
# check "Credential config: no removed keys or mint methods" \
#   'optional_metadata|iam_with_cos|dynamic_s3|oauth2_token_and_s3' \
#   "$docs"

# Deliberately NOT a check: `user_token_header` / `X-Warden-User-Token`.
#
# Unlike the patterns above, naming a retired header is often the correct thing
# for a doc to do — a reader who configured it needs to be told it is gone, so
# the reference pages carry it inside "changed in v0.20.0" callouts. A grep
# cannot tell a warning from a recommendation, so this one stays a review
# concern rather than an automated gate.

if [ "$status" -ne 0 ]; then
  printf 'Documentation invariants failed.\n'
  printf 'These patterns name syntax the server rejects — fix the docs, or if a\n'
  printf 'mention is deliberately historical, reword it so it does not read as\n'
  printf 'current guidance.\n'
fi

exit "$status"
