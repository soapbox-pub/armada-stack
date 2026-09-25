#!/usr/bin/env bash
# Back up everything in this stack that cannot be regenerated.
#
#   ./scripts/backup.sh [--quick] [DIR]        default DIR: ./backups
#
# Writes DIR/<UTC timestamp>/ holding:
#
#   env                    .env — RELAY_NSEC and PUSH_NSEC are identities every
#                          client already trusts; losing them is unrecoverable
#   push-storage.tgz       per-domain VAPID keys; lost = every browser push
#                          subscription silently invalidated
#   caddy-data.tgz         ACME account + certs; lost = re-issue into Let's
#                          Encrypt's duplicate-certificate rate limit
#   opensearch-data.tgz    every event on the relay          (not with --quick)
#   blossom-data.tgz       every uploaded blob + its index   (not with --quick)
#
# --quick takes only the first three: small, and safe to take live. A full
# backup STOPS relay, opensearch and blossom while it copies them, because a tar
# of a live Lucene index or SQLite file is not a consistent snapshot — expect a
# few minutes of downtime, proportional to the data. For no-downtime backups of
# the big two, use your provider's volume/droplet snapshots instead.
#
# The archive holds secrets: it is written mode 700, and should be copied OFF
# the server — a backup on the disk it is backing up protects against mistakes,
# not against losing the server.
#
# Restore, onto a stopped stack (`docker compose down`, NOT `down -v`):
#   cp <backup>/env .env
#   docker run --rm -i -v armada_<volume>:/v alpine:3.22 \
#     sh -c 'rm -rf /v/* && tar xzf - -C /v' < <backup>/<volume>.tgz
#   docker compose up -d
set -euo pipefail

STACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$STACK_DIR"

QUICK=0
DIR=""
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    -h|--help) sed -n '2,/^set -e/p' "$0" | sed 's/^# \{0,1\}//; /^set -e/d'; exit 0 ;;
    *) DIR="$arg" ;;
  esac
done
[ -f .env ] || { echo "no .env here — nothing to back up" >&2; exit 1; }

OUT="${DIR:-$STACK_DIR/backups}/$(date -u +%Y%m%dT%H%M%SZ)"
umask 077
mkdir -p "$OUT"
chmod 700 "$OUT"

# Streamed out of a throwaway container rather than bind-mounting OUT into it:
# no SELinux relabel needed, and the container never sees the host path.
# docker-compose.yml names the project `armada`, so the volumes are
# armada_<name> — unless COMPOSE_PROJECT_NAME overrides it, from the
# environment or from .env (where Compose itself would read it).
PROJECT="${COMPOSE_PROJECT_NAME:-$(sed -n 's/^COMPOSE_PROJECT_NAME=//p' .env | tail -1)}"
PROJECT="${PROJECT:-armada}"
dump() {
  local vol="${PROJECT}_$1"
  if ! docker volume inspect "$vol" >/dev/null 2>&1; then
    echo "  skip  $1 (no such volume yet)"
    return
  fi
  docker run --rm --quiet -v "$vol":/v:ro alpine:3.22 tar czf - -C /v . > "$OUT/$1.tgz"
  echo "  ok    $1  ($(du -h "$OUT/$1.tgz" | cut -f1))"
}

echo "Backing up to $OUT"
cp .env "$OUT/env"
echo "  ok    .env"
dump push-storage
dump caddy-data

if [ "$QUICK" -eq 0 ]; then
  echo "  stopping relay, opensearch, blossom for a consistent copy"
  # Whatever happens below, bring them back.
  trap 'docker compose start opensearch relay blossom >/dev/null 2>&1' EXIT
  docker compose stop relay blossom opensearch >/dev/null 2>&1
  dump opensearch-data
  dump blossom-data
  docker compose start opensearch relay blossom >/dev/null 2>&1
  trap - EXIT
  echo "  restarted"
fi

echo "Done. Copy $OUT off this server."
