#!/usr/bin/env bash
# Update a running stack to the latest stack release.
#
#   ./scripts/update.sh
#
# A stack release is this repo's pins moving together — image digests, the
# client's git ref, LiveKit's version — so updating is: fetch the glue, then
# rebuild/pull/recreate whatever the new pins changed. `.env` is never touched,
# so no identity rotates.
#
# Takes a --quick backup first (secrets, push keys, certs: small and live-safe);
# see backup.sh for a full one.
set -euo pipefail

STACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$STACK_DIR"
[ -f .env ] || { echo "no .env — run scripts/bootstrap.sh first" >&2; exit 1; }

# Where the glue comes from when this checkout has no .git — which is how the
# DigitalOcean image ships, since the bake strips it. deploy.env can override.
STACK_REPO="${STACK_REPO:-https://relay.ngit.dev/npub1scvyzz02ayma34hesz62pdrd5nhsmxp74hjq8msmfs9khh3r3drsnw68d8/armada-stack.git}"
STACK_REF="${STACK_REF:-}"
# shellcheck disable=SC1091
[ -r /etc/armada/deploy.env ] && . /etc/armada/deploy.env

./scripts/backup.sh --quick
echo

echo "Fetching the stack"
# Fetched by ref into FETCH_HEAD rather than `git pull`, so it works the same
# with or without an upstream branch configured.
if [ -d .git ]; then
  before="$(git rev-parse HEAD)"
  git fetch -q origin "${STACK_REF:-HEAD}"
  git merge -q --ff-only FETCH_HEAD
else
  # First update of a baked image: adopt the published repo in place. `.env`
  # and backups/ are gitignored, so the hard reset leaves them alone; any hand
  # edit to a tracked file (a config/ tweak) is overwritten, and listed first.
  before=""
  git init -q
  git remote add origin "$STACK_REPO"
  git fetch -q origin "${STACK_REF:-HEAD}"
  git read-tree FETCH_HEAD
  changed="$(git diff --name-only)"
  [ -n "$changed" ] && printf 'Replacing local changes to:\n%s\n' "$changed"
  git reset -q --hard FETCH_HEAD
fi
after="$(git rev-parse HEAD)"
if [ -n "$before" ] && [ "$before" = "$after" ]; then
  echo "Already at the latest stack release ($(git rev-parse --short HEAD)); reconciling anyway."
fi

# Same order as firstboot: the client build first, so it does not compete with
# a running OpenSearch for memory more than it must. BuildKit caches it, so an
# unchanged client ref is a no-op.
echo "Building the client"
docker compose build armada
echo "Pulling images"
docker compose pull --ignore-buildable
echo "Recreating what changed"
docker compose up -d --wait --wait-timeout 600 --remove-orphans

docker compose ps
docker image prune -f >/dev/null
echo "Updated to $(git rev-parse --short HEAD)."
