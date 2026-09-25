#!/usr/bin/env bash
# Shared first-boot provisioner, and the one place the server boot sequence is
# written down. Every server path runs THIS file: cloud-init.yml (any provider
# that takes user-data) execs it out of the freshly-cloned stack, and the
# DigitalOcean Packer image runs it from armada-firstboot.service. A second copy
# of these steps is a second thing to drift, so there isn't one.
#
# It is self-locating: STACK_DIR is derived from this file's own path
# (deploy/cloud-init/firstboot.sh -> two levels up), so nothing hardcodes
# /opt/armada and the script is correct wherever the stack is cloned.
#
# Nothing here depends on a local path: the base compose file pulls pinned
# images and builds the client from a pinned git URL, so the only thing that
# has to be on disk is this stack checkout itself.
#
# Idempotent: guarded by a done-marker and by `.env` existence, so a re-run
# (a reboot, a manual retry after fixing the domain) resumes rather than
# rotating keys or repeating outbound work.
set -euo pipefail

# ── Locate ourselves and the config ──────────────────────────────────────────
STACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Where DOMAIN/EMAIL (and optional overrides) are written — by cloud-init's
# write_files, by the first-login prompt (armada-setup), or by hand. Override
# for testing with ARMADA_DEPLOY_ENV.
DEPLOY_ENV="${ARMADA_DEPLOY_ENV:-/etc/armada/deploy.env}"

MARK="${ARMADA_MARK:-/var/lib/armada/.provisioned}"
LOG="${ARMADA_LOG:-/var/log/armada-firstboot.log}"

mkdir -p "$(dirname "$MARK")"

# One run at a time: the boot unit and an operator's `armada-setup` can race.
exec 9>"$(dirname "$MARK")/.firstboot.lock"
flock -n 9 || { echo "firstboot is already running — tail -f $LOG"; exit 0; }

exec > >(tee -a "$LOG") 2>&1
echo "armada firstboot $(date -u +%FT%TZ) — stack at $STACK_DIR"

cd "$STACK_DIR"

# Already provisioned: this is a reboot. Docker's restart policy has probably
# brought everything back already; `up -d` reconciles anything that did not,
# without rebuilding the client.
if [ -f "$MARK" ]; then
  echo "already provisioned ($MARK exists); reconciling"
  docker compose up -d
  exit 0
fi

# An unconfigured box is WAITING, not broken: it booted fine, it just has no
# domain yet. Exit 0 so the systemd oneshot succeeds and the operator is told
# what to do, rather than the unit entering `failed`. No marker is written, so
# the next boot — or `armada-setup`, or a manual re-run — retries. Genuine
# failures (docker install, compose) still fail hard via set -e.
waiting() { echo "$*"; exit 0; }

# ── Config ───────────────────────────────────────────────────────────────────
[ -f "$DEPLOY_ENV" ] || \
  waiting "no config at $DEPLOY_ENV — run armada-setup, or write DOMAIN and EMAIL there and re-run: $0"
# shellcheck disable=SC1090
. "$DEPLOY_ENV"

[ -n "${DOMAIN:-}" ] && [ "$DOMAIN" != "example.com" ] || \
  waiting "$DEPLOY_ENV: DOMAIN is not set — run armada-setup, or set it and re-run: $0"
[ -n "${EMAIL:-}" ] && [ "$EMAIL" != "you@example.com" ] || \
  waiting "$DEPLOY_ENV: EMAIL is not set — run armada-setup, or set it and re-run: $0"

# ── Docker ───────────────────────────────────────────────────────────────────
# Baked in by the Packer image; installed here on the cloud-init path.
if ! command -v docker >/dev/null 2>&1; then
  echo "installing docker"
  curl -fsSL https://get.docker.com | sh
fi
docker info >/dev/null 2>&1 || systemctl enable --now docker

# ── Host sysctls ─────────────────────────────────────────────────────────────
# install-host.sh persisted them in /etc/sysctl.d; apply them live so the first
# `up` never trips before a reboot.
sysctl --system >/dev/null

# ── Secrets ──────────────────────────────────────────────────────────────────
if [ ! -f .env ]; then
  ./scripts/bootstrap.sh --domain "$DOMAIN" --email "$EMAIL"
  # A client-source override from deploy.env belongs in .env, where every
  # later `docker compose` (update.sh included) will see it.
  if [ -n "${ARMADA_BUILD_CONTEXT:-}" ]; then
    echo "ARMADA_BUILD_CONTEXT=$ARMADA_BUILD_CONTEXT" >> .env
  fi
fi

# ── Bring it up ──────────────────────────────────────────────────────────────
# The client build is the slow, memory-hungry step (npm ci + vite build, a few
# minutes). Doing it BEFORE anything else starts keeps it from competing with
# OpenSearch's heap on a 4 GB box.
echo "building the client (this is the slow part: several minutes)"
docker compose build armada
echo "pulling images"
docker compose pull --ignore-buildable
echo "starting the stack"
if ! docker compose up -d --wait --wait-timeout 600; then
  docker compose ps
  echo "the stack did not become healthy — see: cd $STACK_DIR && docker compose logs"
  exit 1
fi

touch "$MARK"
docker compose ps

# DNS is the one step nothing on this box can do. Report rather than block:
# Caddy keeps retrying ACME on its own, so the stack finishes by itself once
# the records exist.
echo
./scripts/check-dns.sh || true

cat <<EOF

armada firstboot done. Once the four names above resolve here, Caddy fetches
certificates by itself — then open https://armada.$DOMAIN
EOF
