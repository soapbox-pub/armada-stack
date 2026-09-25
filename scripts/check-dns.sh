#!/usr/bin/env bash
# Do the four public names resolve to this host?
#
#   ./scripts/check-dns.sh
#
# The one setup step nothing on the server can do, and the most common reason
# a fresh deploy "doesn't work": Caddy cannot get a certificate for a name that
# does not resolve here, and says so only in its own log. Exits 0 when all four
# resolve to an address on this host, 1 otherwise.
#
# Compared against the host's own interface addresses, which is right on a VPS
# with the public IP on eth0 (DigitalOcean, Hetzner, Vultr, Linode). Behind NAT
# (AWS, Lightsail, a home router) the public IP is not on any interface, so a
# correct record shows as "elsewhere" — the message says so rather than guess.
set -euo pipefail

STACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$STACK_DIR/.env"
[ -f "$ENV_FILE" ] || { echo "no .env — run scripts/bootstrap.sh first" >&2; exit 1; }

site() { sed -n "s|^$1=[a-z]*://||p" "$ENV_FILE" | head -1; }
HOSTS="$(site ARMADA_SITE) $(site AV_SITE) $(site RELAY_SITE) $(site BLOSSOM_SITE)"

case "$HOSTS" in
  *.localhost*) echo "local mode — *.localhost needs no DNS"; exit 0 ;;
esac
# Behind an external proxy the records point at THAT, not here.
if grep -q '^ARMADA_SITE=http://' "$ENV_FILE"; then
  echo "behind-proxy mode — the names should resolve to your proxy, not this host"
  exit 0
fi

LOCAL_ADDRS="$(ip -o addr show scope global 2>/dev/null | awk '{sub(/\/.*/, "", $4); print $4}')"

echo "DNS"
FAIL=0
ELSEWHERE=0
for h in $HOSTS; do
  addrs="$(getent ahosts "$h" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')"
  if [ -z "$addrs" ]; then
    printf '  \033[31mmissing\033[0m    %s does not resolve yet\n' "$h"
    FAIL=1
    continue
  fi
  here=0
  for a in $addrs; do
    printf '%s\n' "$LOCAL_ADDRS" | grep -qxF "$a" && here=1
  done
  if [ "$here" -eq 1 ]; then
    printf '  \033[32mok\033[0m         %s -> %s\n' "$h" "$addrs"
  else
    printf '  \033[33melsewhere\033[0m  %s -> %s\n' "$h" "$addrs"
    FAIL=1; ELSEWHERE=1
  fi
done

if [ "$FAIL" -ne 0 ]; then
  echo
  echo "  Point an A (and/or AAAA) record for each name above at this server."
  echo "  This host's addresses: $(printf '%s ' $LOCAL_ADDRS)"
  if [ "$ELSEWHERE" -eq 1 ]; then
    echo "  (Behind NAT, the public IP is not on any interface; if the records"
    echo "  point at your public IP, they are right and this can be ignored.)"
  fi
  echo "  New records can take a few minutes to propagate. Re-run this to check."
fi
exit "$FAIL"
