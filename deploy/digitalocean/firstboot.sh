#!/usr/bin/env bash
# Shared first-boot provisioner for the droplet, and the one place the boot
# sequence is written down. BOTH the cloud-init path (Path A) and the Packer
# image (Path B) run THIS file — cloud-init execs it out of the freshly-cloned
# stack, Packer bakes the stack in and a systemd unit runs it on first boot. A
# second copy of these steps is a second thing to drift, so there isn't one.
#
# It is self-locating: STACK_DIR is derived from this file's own path
# (deploy/digitalocean/firstboot.sh -> two levels up), so nothing hardcodes
# /opt/armada and the script is correct wherever the stack is cloned.
#
# NOTHING HERE DEPENDS ON A LOCAL PATH. In pull mode the relay/broker/push
# images come from ncontainer.io and the client builds from a git-URL context
# (docker-compose.pull.yml), so the only thing that has to be on disk is this
# stack checkout itself — which is exactly the repo this file lives in.
#
# Idempotent: guarded by a done-marker and by `.env`/clone existence checks, so
# a re-run (cloud-init re-execution, a manual retry after fixing DNS or the
# domain) resumes rather than rotating keys or repeating outbound work.
set -euo pipefail

# ── Locate ourselves and the config ──────────────────────────────────────────
STACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Where DOMAIN/EMAIL (and optional overrides) are written. cloud-init and the
# Marketplace form both land here; override for testing with ARMADA_DEPLOY_ENV.
DEPLOY_ENV="${ARMADA_DEPLOY_ENV:-/etc/armada/deploy.env}"

MARK="${ARMADA_MARK:-/var/lib/armada/.provisioned}"
LOG="${ARMADA_LOG:-/var/log/armada-firstboot.log}"

mkdir -p "$(dirname "$MARK")"
exec > >(tee -a "$LOG") 2>&1
echo "armada firstboot $(date -u +%FT%TZ) — stack at $STACK_DIR"

if [ -f "$MARK" ]; then
  echo "already provisioned ($MARK exists); bringing the stack up in case it is down"
fi

# An unconfigured box is WAITING, not broken: it booted fine, it just has no
# domain yet. Exit 0 so the systemd oneshot (Path B) succeeds and the operator
# is told what to do, rather than the unit entering `failed`. No marker is
# written, so the next boot — or a manual re-run after editing deploy.env —
# retries. Genuine failures (docker install, compose) still fail hard via set -e.
waiting() { echo "$*"; exit 0; }

# ── Config ───────────────────────────────────────────────────────────────────
[ -f "$DEPLOY_ENV" ] || \
  waiting "no config at $DEPLOY_ENV — write DOMAIN and EMAIL there, then re-run: $0"
# shellcheck disable=SC1090
. "$DEPLOY_ENV"

[ -n "${DOMAIN:-}" ] && [ "$DOMAIN" != "example.com" ] || \
  waiting "$DEPLOY_ENV: set DOMAIN to your real domain, then re-run: $0"
[ -n "${EMAIL:-}" ] && [ "$EMAIL" != "you@example.com" ] || \
  waiting "$DEPLOY_ENV: set EMAIL to your real contact address, then re-run: $0"

# ── Docker ───────────────────────────────────────────────────────────────────
# Baked in by Packer; installed here on the cloud-init path. Either way, present
# after this block.
if ! command -v docker >/dev/null 2>&1; then
  echo "installing docker"
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
fi

# ── Host sysctls ─────────────────────────────────────────────────────────────
# Host-kernel settings a container inherits and cannot set (preflight explains
# both). cloud-init/Packer persist them in /etc/sysctl.d; apply them here too so
# a first `up` never trips even before a reboot. Idempotent.
sysctl -w vm.max_map_count=262144 >/dev/null 2>&1 || true
sysctl -w net.core.rmem_max=5000000 >/dev/null 2>&1 || true

# ── Bring it up ──────────────────────────────────────────────────────────────
cd "$STACK_DIR"

# --pull: no sibling checkout required (images pulled, client built from git URL).
if [ ! -f .env ]; then
  ./scripts/bootstrap.sh --domain "$DOMAIN" --email "$EMAIL" --pull
fi

# An optional client-source pin. deploy.env is sourced above, which makes
# ARMADA_BUILD_CONTEXT a shell var but not an environment one — and docker
# compose reads the process ENVIRONMENT (and .env), not this shell's unexported
# vars. Export it so docker-compose.pull.yml's ${ARMADA_BUILD_CONTEXT:-…} sees
# it; unset, the compose default (the public mirror) stands.
[ -n "${ARMADA_BUILD_CONTEXT:-}" ] && export ARMADA_BUILD_CONTEXT

# Pull the three, build the one. The client build runs entirely inside its own
# node:22-alpine stage from a git-URL context, so the host needs only Docker.
docker compose -f docker-compose.yml -f docker-compose.pull.yml up -d --build armada

touch "$MARK"
cat <<EOF

armada firstboot done. If you have not already, point four DNS records at this
host's public IP — Caddy cannot issue TLS certificates until they resolve here:

  armada.$DOMAIN   av.$DOMAIN   relay.$DOMAIN   blossom.$DOMAIN

Then open https://armada.$DOMAIN
EOF
