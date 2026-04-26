#!/bin/sh
# Idempotent Forgejo admin user bootstrap for the Warden policy-hygiene tutorial.
# Creates the 'siteowner' admin if it doesn't already exist.
set -eu

FORGEJO="forgejo --config /data/gitea/conf/app.ini"

if $FORGEJO admin user list 2>/dev/null | awk '{print $2}' | grep -qx siteowner; then
  echo "forgejo-init: 'siteowner' already exists"
  exit 0
fi

$FORGEJO admin user create \
  --admin --username siteowner --password warden-tutorial \
  --email siteowner@local --must-change-password=false

echo "forgejo-init: created admin 'siteowner' / 'warden-tutorial'"
