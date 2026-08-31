#!/usr/bin/env bash
# Bake the Armada stack into a DigitalOcean snapshot. Packer runs this as root
# on a throwaway build droplet (see armada.pkr.hcl); the snapshot it takes
# afterwards is what a Marketplace 1-Click droplet is made from.
#
# The division of labour with firstboot.sh is deliberate: everything that is the
# SAME for every droplet is done HERE, at bake time (Docker, the stack checkout,
# the sysctls, pre-pulled images); everything that is PER-DEPLOYMENT — the
# domain, the generated secrets, the actual `up` — is left to firstboot.sh on
# the operator's first real boot. That split is what lets the image carry NO
# secret and NO operator-specific value, which is the hard requirement for
# passing DO Marketplace review.
#
# The stack source is uploaded by Packer's file provisioner to STAGING (a plain
# copy of the maintainer's checkout), not cloned here — so an image can be built
# before the stack is published anywhere. firstboot.sh then needs no network for
# the glue itself; only the images and the client's git context are fetched, at
# first boot, from URLs.
set -euo pipefail

STAGING="${1:-/tmp/armada-stack}"
STACK_DIR=/opt/armada/stack

# The published image namespace (see .images.env / docker-compose.pull.yml). The
# three refs are pre-pulled so the first real boot doesn't wait on them.
IMAGES_NPUB=npub10qdp2fc9ta6vraczxrcs8prqnv69fru2k6s2dj48gqjcylulmtjsg9arpj
IMAGES="armada-relay armada-broker armada-push"

echo "==> provisioning armada image"
export DEBIAN_FRONTEND=noninteractive

# ── Base packages ────────────────────────────────────────────────────────────
# ufw for the on-host firewall firstboot expects; git in case an operator wants
# to update the baked checkout in place; ca-certificates/curl for get.docker.com.
apt-get update -y
apt-get install -y --no-install-recommends ca-certificates curl git ufw

# ── Docker ───────────────────────────────────────────────────────────────────
# Baked in so the first real boot spends its time on pulls and the client build,
# not on installing a package manager's worth of Docker.
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable docker

# ── Host sysctls ─────────────────────────────────────────────────────────────
# Persisted for every boot. OpenSearch refuses to start below max_map_count;
# LiveKit drops inbound media below rmem_max. Both are host-kernel, not settable
# from compose. firstboot also applies them live before the first `up`.
cat > /etc/sysctl.d/99-armada.conf <<'SYSCTL'
vm.max_map_count=262144
net.core.rmem_max=5000000
SYSCTL

# ── The stack checkout ───────────────────────────────────────────────────────
mkdir -p /opt/armada
rm -rf "$STACK_DIR"
cp -a "$STAGING" "$STACK_DIR"
# Never bake a secret into a public image. Three sources, all stripped here:
#   .env          the generated stack secrets (RELAY_NSEC, PUSH_NSEC, LiveKit)
#   .images.env   the ncontainer publisher nsec
#   .git          the maintainer's clone carries repo-local git config, and this
#                 repo sets `nostr.nsec` there (the ngit signing key) — a working
#                 tree's .git/config is a secret the file provisioner copies
#                 verbatim. The baked image needs no history: firstboot builds
#                 from URLs, not from this checkout's git objects.
rm -rf "$STACK_DIR/.env" "$STACK_DIR/.images.env" "$STACK_DIR/.git"

# ── deploy.env skeleton ──────────────────────────────────────────────────────
# The operator's user-data (or a Marketplace form, or hand editing) overwrites
# this. The example.com placeholders are load-bearing: firstboot.sh REFUSES
# them, so an unconfigured droplet waits rather than booting a stack on a domain
# nobody owns. No secret goes here.
mkdir -p /etc/armada
if [ ! -f /etc/armada/deploy.env ]; then
  cat > /etc/armada/deploy.env <<'DEPLOYENV'
# Set these, then reboot (or `systemctl start armada-firstboot`).
DOMAIN=example.com
EMAIL=you@example.com

# Optional: pin the client source. Default is the public mirror's default
# branch; append #<tag|branch|sha> for a reproducible build.
#ARMADA_BUILD_CONTEXT=https://github.com/soapbox-pub/armada.git#v1.4.2
DEPLOYENV
  chmod 600 /etc/armada/deploy.env
fi

# ── Pre-pull the three images ────────────────────────────────────────────────
# Best-effort: an image not yet published (or a transient relay/Blossom outage)
# must not fail the BAKE — firstboot pulls again anyway, and an un-pre-pulled
# image only makes the first boot slower, not broken.
for repo in $IMAGES; do
  ref="ncontainer.io/${IMAGES_NPUB}/${repo}:latest"
  echo "==> pre-pull $ref"
  docker pull "$ref" || echo "   (skip: $ref not pullable at bake time; firstboot will fetch it)"
done

# ── First-boot unit ──────────────────────────────────────────────────────────
install -m 0644 "$STACK_DIR/deploy/digitalocean/armada-firstboot.service" \
  /etc/systemd/system/armada-firstboot.service
systemctl enable armada-firstboot.service

# ── MOTD ─────────────────────────────────────────────────────────────────────
# DO shows /etc/motd on SSH login. Tell the operator the one thing they must do.
cat > /etc/motd <<'MOTD'

  Armada stack (self-hosted). To finish setup:

    1. Edit /etc/armada/deploy.env — set DOMAIN and EMAIL.
    2. Point four DNS records at this droplet's IP:
         armada.<domain>  av.<domain>  relay.<domain>  blossom.<domain>
    3. systemctl start armada-firstboot   (or just reboot)

  Progress:  tail -f /var/log/armada-firstboot.log
  Docs:      /opt/armada/stack/deploy/digitalocean/README.md

MOTD

# ── Remove the staging upload ─────────────────────────────────────────────────
# The file provisioner uploaded the maintainer's checkout VERBATIM, so the
# staging tree still carries .git (and its nsec) and any local .env even though
# the BAKED copy at $STACK_DIR does not. DO's 90-cleanup.sh does not touch
# /tmp/armada-stack, so strip it here or it rides into the snapshot on the build
# droplet's disk.
rm -rf "$STAGING"

echo "==> provision done"
