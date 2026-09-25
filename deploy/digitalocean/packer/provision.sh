#!/usr/bin/env bash
# Bake the Armada stack into a DigitalOcean snapshot. Packer runs this as root
# on a throwaway build droplet (see armada.pkr.hcl); the snapshot it takes
# afterwards is what a Marketplace 1-Click droplet is made from.
#
# The division of labour with firstboot.sh is deliberate: everything that is the
# SAME for every droplet is done HERE, at bake time (Docker, the stack checkout,
# the host pieces, pre-pulled images); everything that is PER-DEPLOYMENT — the
# domain, the generated secrets, the client build, the actual `up` — is left to
# firstboot.sh on the operator's first real boot. That split is what lets the
# image carry NO secret and NO operator-specific value, which is the hard
# requirement for passing DO Marketplace review.
#
# The stack source arrives in STAGING as a `git archive` of the maintainer's
# HEAD (see armada.pkr.hcl), not cloned here — so an image is exactly a commit,
# buildable before that commit is published. update.sh adopts the published
# repo in place on the first update.
set -euo pipefail

STAGING="${1:-/tmp/armada-stack}"
STACK_DIR=/opt/armada/stack

echo "==> provisioning armada image"
export DEBIAN_FRONTEND=noninteractive

# ── Base packages ────────────────────────────────────────────────────────────
apt-get update -y
apt-get install -y --no-install-recommends ca-certificates curl git ufw

# ── Docker ───────────────────────────────────────────────────────────────────
# Baked in so the first real boot spends its time on the client build, not on
# installing a package manager's worth of Docker.
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable docker

# ── The stack checkout ───────────────────────────────────────────────────────
mkdir -p /opt/armada
rm -rf "$STACK_DIR"
cp -a "$STAGING" "$STACK_DIR"
# Never bake a secret into a public image. A `git archive` cannot contain
# `.env`, backups/ or .git (a maintainer's clone can carry an ngit
# `nostr.nsec` in its config) — strip them anyway, in case this script is ever
# fed a raw checkout instead.
rm -rf "$STACK_DIR/.env" "$STACK_DIR/backups" "$STACK_DIR/.git"

# Boot unit, armada-setup + its first-login prompt, deploy.env skeleton, MOTD —
# the same host pieces cloud-init installs, from the same script.
bash "$STACK_DIR/deploy/cloud-init/install-host.sh"

# ── Pre-pull every pinned image ──────────────────────────────────────────────
# Read straight out of docker-compose.yml (`docker compose pull` cannot run
# here: every ${VAR:?} fails without a .env). Best-effort — an unpullable image
# only makes the first boot slower, since firstboot pulls again.
grep -E '^[[:space:]]+image:' "$STACK_DIR/docker-compose.yml" | awk '{print $2}' |
while read -r ref; do
  echo "==> pre-pull $ref"
  docker pull -q "$ref" || echo "   (skip: $ref not pullable at bake time; firstboot will fetch it)"
done
# The client's build stages, so its first build downloads only its own source.
for ref in node:22-alpine nginx:1.27-alpine; do
  docker pull -q "$ref" || true
done

# ── Remove the staging upload ─────────────────────────────────────────────────
# DO's 90-cleanup.sh does not touch /tmp/armada-stack; remove it here so the
# snapshot holds one copy of the stack, not two.
rm -rf "$STAGING"

echo "==> provision done"
