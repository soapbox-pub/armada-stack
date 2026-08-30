#!/usr/bin/env bash
# Check the things that fail slowly or confusingly if they are wrong.
#
# Run on its own (`./scripts/preflight.sh`) or as the first thing bootstrap.sh
# does. Exits non-zero if anything is a hard blocker; warnings do not fail.
set -euo pipefail

STACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAIL=0

# --pull: the relay, broker and push images are PULLED from ncontainer.io
# (docker-compose.pull.yml) rather than built, so only ../armada — the one image
# still built locally — has to be present. Without it, all four siblings are
# required, which is the source-build default.
PULL=0
for arg in "$@"; do
  case "$arg" in
    --pull) PULL=1 ;;
  esac
done

say()  { printf '  %s\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m    %s\n' "$*"; }
warn() { printf '  \033[33mwarn\033[0m  %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAIL=1; }

echo "Preflight"
echo

# ── Docker ───────────────────────────────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
  bad "docker not found on PATH"
elif ! docker info >/dev/null 2>&1; then
  bad "docker is installed but the daemon is not reachable (permissions? not running?)"
else
  ok "docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?')"
fi

# The relay image uses named build contexts (`additional_contexts`), which
# needs Compose v2.17+ and BuildKit. Anything older fails at build time with a
# confusing "COPY --from" error rather than a version complaint.
if docker compose version >/dev/null 2>&1; then
  ok "docker compose $(docker compose version --short 2>/dev/null || echo '?')"
else
  bad "'docker compose' (v2+) not available; the v1 'docker-compose' binary will not work"
fi

# ── Sibling checkouts ────────────────────────────────────────────────────────
# This repo is glue and contains no application source.
# Checked by their manifest rather than by .git: a deployed copy is often an
# rsync or a tarball with no history, and that is a perfectly good build source.
#
# In --pull mode the relay, broker and push images come from ncontainer.io, so
# only ../armada (still built locally, because its VITE_* config is baked at
# build time from this deployment's own hostnames) has to be here.
if [ "$PULL" -eq 1 ]; then
  SIBLINGS="armada"
else
  SIBLINGS="armada armada-av ditto-relay nostr-push"
fi
for repo in $SIBLINGS; do
  if [ -f "$STACK_DIR/../$repo/package.json" ]; then
    ok "../$repo"
  else
    if [ "$PULL" -eq 1 ]; then
      bad "../$repo is missing — pull mode still builds the client from it"
    else
      bad "../$repo is missing — the stack builds every image from sibling checkouts"
    fi
  fi
done

# ── OpenSearch's one host requirement ────────────────────────────────────────
# Too low and OpenSearch refuses to start with a bootstrap check failure, which
# surfaces as the relay crash-looping on an unreachable database.
if [ -r /proc/sys/vm/max_map_count ]; then
  mmc="$(cat /proc/sys/vm/max_map_count)"
  if [ "$mmc" -ge 262144 ]; then
    ok "vm.max_map_count = $mmc"
  else
    bad "vm.max_map_count = $mmc, OpenSearch needs >= 262144
        sudo sysctl -w vm.max_map_count=262144
        echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-opensearch.conf"
  fi
else
  warn "cannot read vm.max_map_count (not Linux?) — OpenSearch needs it >= 262144"
fi

# LiveKit warns at boot if this is small and drops packets under real load. It
# is only a ceiling — raising it allocates nothing — so it is safe to set on a
# shared host. Inside an unprivileged LXC it is NOT settable: it belongs to the
# host kernel, so set it on the hypervisor, not in the container.
if [ -r /proc/sys/net/core/rmem_max ]; then
  rmem="$(cat /proc/sys/net/core/rmem_max)"
  if [ "$rmem" -ge 5000000 ]; then
    ok "net.core.rmem_max = $rmem"
  else
    warn "net.core.rmem_max = $rmem, LiveKit wants >= 5000000 for production voice
        sudo sysctl -w net.core.rmem_max=5000000
        echo 'net.core.rmem_max=5000000' | sudo tee /etc/sysctl.d/99-livekit.conf"
  fi
fi

# ── LiveKit's UDP receive buffer ─────────────────────────────────────────────
# A host-level sysctl, not a namespaced one, so it CANNOT be set from compose —
# the container inherits whatever the host has. Too small and LiveKit drops
# inbound media under load, which users experience as choppy audio rather than
# as any kind of error. LiveKit warns about this at startup and suggests 5 MB.
if [ -r /proc/sys/net/core/rmem_max ]; then
  rmem="$(cat /proc/sys/net/core/rmem_max)"
  if [ "$rmem" -ge 5000000 ]; then
    ok "net.core.rmem_max = $rmem"
  else
    warn "net.core.rmem_max = $rmem, LiveKit wants >= 5000000 for production voice
        sudo sysctl -w net.core.rmem_max=5000000
        echo 'net.core.rmem_max=5000000' | sudo tee /etc/sysctl.d/99-livekit.conf"
  fi
fi

# ── Are we inside a container ourselves? ─────────────────────────────────────
# An unprivileged LXC cannot raise RLIMIT_MEMLOCK, and the failure names
# neither memlock nor OpenSearch — it is a bare "error setting rlimit type 8".
# Worth naming before it happens.
VIRT=""
command -v systemd-detect-virt >/dev/null 2>&1 && VIRT="$(systemd-detect-virt -c 2>/dev/null || true)"
if [ -n "$VIRT" ] && [ "$VIRT" != "none" ]; then
  warn "running inside '$VIRT' — add the LXC override or OpenSearch will not start:
        docker compose -f docker-compose.yml -f docker-compose.lxc.yml up -d"
fi

# ── Memory ───────────────────────────────────────────────────────────────────
# OpenSearch alone takes a 1 GB heap by default, and the client image is built
# with a full npm install + vite build.
if [ -r /proc/meminfo ]; then
  kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
  gb=$(( kb / 1024 / 1024 ))
  if [ "$gb" -ge 4 ]; then
    ok "${gb} GB RAM"
  else
    warn "${gb} GB RAM — tight. Lower OPENSEARCH_JAVA_OPTS in .env, or expect OOM kills"
  fi
fi

# ── Ports ────────────────────────────────────────────────────────────────────
# Only the published ones. A conflict here is a confusing bind error at `up`.
check_port() {
  local port="$1" proto="$2" what="$3"
  if command -v ss >/dev/null 2>&1; then
    local flag="-ltn"; [ "$proto" = udp ] && flag="-lun"
    if ss $flag 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}\$"; then
      warn "${proto}/${port} is already in use (${what})"
    fi
  fi
}
check_port 80 tcp "Caddy HTTP"
check_port 443 tcp "Caddy HTTPS"
check_port 7881 tcp "LiveKit ICE/TCP"
check_port 7882 udp "LiveKit media mux"

echo
if [ "$FAIL" -ne 0 ]; then
  echo "Preflight failed."
  exit 1
fi
echo "Preflight passed."
