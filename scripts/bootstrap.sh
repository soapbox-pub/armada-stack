#!/usr/bin/env bash
# Generate .env: every secret the stack needs, plus the values that have to
# agree across services and would otherwise be copied by hand.
#
#   ./scripts/bootstrap.sh --domain example.com --email you@example.com
#   ./scripts/bootstrap.sh --local
#
# Run once. It refuses to clobber an existing .env without --force, because
# regenerating RELAY_NSEC changes the relay's published identity and
# regenerating PUSH_NSEC orphans every push subscription already registered
# against the old pubkey.
set -euo pipefail

STACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$STACK_DIR/.env"

# Pinned rather than floating: this is the library that mints the stack's
# long-lived identities, fetched at bootstrap time into a throwaway container.
NOSTR_TOOLS_VERSION="2.17.0"

DOMAIN=""
EMAIL=""
LOCAL=0
FORCE=0
BEHIND_PROXY=""
PULL=0

die() { printf '\033[31merror\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
Usage:
  bootstrap.sh --domain <domain> --email <email>   public deployment, auto-TLS
  bootstrap.sh --local                             *.localhost, plain HTTP
  bootstrap.sh --domain <d> --behind-proxy <cidr>  external proxy terminates TLS

Options:
  --domain <d>   base domain; yields armada.<d>, av.<d>, relay.<d>, blossom.<d>
  --email <e>    ACME registration contact, also the push VAPID subject
  --local        local mode: no DNS, no certs, no email needed
  --behind-proxy <cidr>
                 an external reverse proxy terminates TLS and forwards here.
                 The stack binds plain HTTP; clients still see https/wss, so
                 the two sets of URLs diverge. <cidr> is that proxy's address
                 (e.g. 192.168.1.121/32) — it is trusted to report client IPs.
  --pull         pull the relay, broker and push images from ncontainer.io and
                 build the client from a git-URL context instead of local
                 checkouts; no sibling repo has to be present. Relaxes the
                 preflight sibling check to match.
  --force        overwrite an existing .env (destroys the current identities)
  -h, --help     this
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --email)  EMAIL="${2:-}";  shift 2 ;;
    --local)  LOCAL=1;         shift ;;
    --behind-proxy) BEHIND_PROXY="${2:-}"; shift 2 ;;
    --pull)   PULL=1;          shift ;;
    --force)  FORCE=1;         shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -e "$ENV_FILE" ] && [ "$FORCE" -ne 1 ] && \
  die ".env already exists. Delete it or pass --force (this rotates every key)."

# ── Addressing ───────────────────────────────────────────────────────────────
if [ "$LOCAL" -eq 1 ]; then
  [ -n "$DOMAIN" ] && die "--local and --domain are mutually exclusive"
  [ -n "$BEHIND_PROXY" ] && die "--local and --behind-proxy are mutually exclusive"
  BIND_SCHEME="http"; PUB_SCHEME="http"; WS_SCHEME="ws"
  DOMAIN="localhost"
  # nostr-push rejects an empty VAPID_SUBJECT at boot, so local mode still
  # needs some contact URI even though nothing will ever read it.
  [ -n "$EMAIL" ] || EMAIL="admin@localhost"
else
  if [ -z "$DOMAIN" ] && [ -t 0 ]; then
    printf 'Base domain (e.g. example.com): '; read -r DOMAIN
  fi
  [ -n "$DOMAIN" ] || die "--domain is required (or use --local)"

  if [ -n "$BEHIND_PROXY" ]; then
    # The external proxy owns TLS. This stack binds plain HTTP on the LAN,
    # but every URL baked into the client — and the origin the broker checks
    # signed grants against — must still be the PUBLIC https one the browser
    # actually used. That divergence is the whole reason for this mode.
    BIND_SCHEME="http"; PUB_SCHEME="https"; WS_SCHEME="wss"
    # No ACME here, so an email is optional; it is still the VAPID subject.
    [ -n "$EMAIL" ] || EMAIL="admin@${DOMAIN}"
  else
    if [ -z "$EMAIL" ] && [ -t 0 ]; then
      printf "Contact email for Let's Encrypt: "; read -r EMAIL
    fi
    [ -n "$EMAIL" ] || die "--email is required for auto-TLS (or use --local)"
    BIND_SCHEME="https"; PUB_SCHEME="https"; WS_SCHEME="wss"
  fi
fi

ARMADA_HOST="armada.${DOMAIN}"
AV_HOST="av.${DOMAIN}"
RELAY_HOST="relay.${DOMAIN}"
BLOSSOM_HOST="blossom.${DOMAIN}"

# In --pull mode no sibling checkout has to be present: the three images come
# from ncontainer.io and the client builds from a git-URL context. Forward the
# flag so preflight relaxes its sibling check to match.
if [ "$PULL" -eq 1 ]; then
  "$STACK_DIR/scripts/preflight.sh" --pull
else
  "$STACK_DIR/scripts/preflight.sh"
fi
echo

# ── Secrets ──────────────────────────────────────────────────────────────────
# /dev/urandom via od: no openssl dependency, no host toolchain.
rand_hex() { od -An -N"${1:-32}" -tx1 /dev/urandom | tr -d ' \n'; }

echo "Generating secrets"

# LiveKit accepts any key/secret pair; the API-prefixed key is only convention.
LIVEKIT_API_KEY="API$(rand_hex 8)"
LIVEKIT_API_SECRET="$(rand_hex 32)"
BLOSSOM_ADMIN_PASSWORD="$(rand_hex 16)"

# The relay identity and the push identity, minted in a throwaway container so
# the host needs no Bun/Node. Piped over stdin rather than bind-mounted: a bind
# mount would need an SELinux relabel on Fedora and friends.
echo "  minting Nostr identities (nostr-tools@${NOSTR_TOOLS_VERSION})"
KEYS="$(
  docker run --rm -i "oven/bun:1" sh -c "
    cd /tmp && cat > keygen.ts && echo '{}' > package.json &&
    bun add nostr-tools@${NOSTR_TOOLS_VERSION} --silent >/dev/null 2>&1 &&
    bun run keygen.ts 2
  " < "$STACK_DIR/scripts/lib/keygen.ts"
)" || die "key generation failed (is the docker daemon reachable, and online?)"

eval "$KEYS"
: "${NSEC_1:?key generation produced no relay nsec}"
: "${NSEC_2:?key generation produced no push nsec}"
: "${HEX_2:?key generation produced no push pubkey}"

RELAY_NSEC="$NSEC_1"
PUSH_NSEC="$NSEC_2"
PUSH_PUBKEY_HEX="$HEX_2"
PUSH_NPUB="$NPUB_2"

# ── Write ────────────────────────────────────────────────────────────────────
umask 077
cat > "$ENV_FILE" <<EOF
# Generated by scripts/bootstrap.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ).
#
# SECRETS. Not in git (see .gitignore). Back it up: RELAY_NSEC is the relay's
# published identity and PUSH_NSEC is the address every client registers its
# push subscriptions against — regenerating either is not a recoverable event.

# ── Addressing ───────────────────────────────────────────────────────────────
# Every hostname the stack answers on. Caddy takes the scheme from these URLs:
# https:// means automatic Let's Encrypt, http:// means no TLS at all.
#
# These are BUILD INPUTS for the client image as well as runtime config, so
# changing one means \`docker compose up -d --build\`, not a restart.
BASE_DOMAIN=${DOMAIN}
ACME_EMAIL=${EMAIL}

# What THIS stack's Caddy binds. http:// here means an external proxy is
# terminating TLS in front of us.
ARMADA_SITE=${BIND_SCHEME}://${ARMADA_HOST}
AV_SITE=${BIND_SCHEME}://${AV_HOST}
RELAY_SITE=${BIND_SCHEME}://${RELAY_HOST}
BLOSSOM_SITE=${BIND_SCHEME}://${BLOSSOM_HOST}

# What CLIENTS see. Baked into the client bundle, signed over by voice grants,
# and published in the relay's NIP-11 document — so these are the browser's
# view, which behind a TLS-terminating proxy is not what we bind above.
ARMADA_PUBLIC_URL=${PUB_SCHEME}://${ARMADA_HOST}
AV_PUBLIC_ORIGIN=${PUB_SCHEME}://${AV_HOST}
RELAY_PUBLIC_URL=${PUB_SCHEME}://${RELAY_HOST}
BLOSSOM_PUBLIC_URL=${PUB_SCHEME}://${BLOSSOM_HOST}

# WebSocket forms. Bare origins — the LiveKit SDK appends /rtc itself, so
# never write it here.
RELAY_WS_URL=${WS_SCHEME}://${RELAY_HOST}
LIVEKIT_WS_URL=${WS_SCHEME}://${AV_HOST}

# Whose X-Forwarded-For we believe. Loopback (i.e. nobody) unless an external
# proxy is in front; see config/caddy/Caddyfile.
TRUSTED_PROXIES=${BEHIND_PROXY:-127.0.0.1/32}

# ── Identities ───────────────────────────────────────────────────────────────
# The relay's own key: it signs trend and NIP-85 assertion events with this.
RELAY_NSEC=${RELAY_NSEC}

# The push gateway's key. PUSH_PUBKEY_HEX is derived from PUSH_NSEC and is used
# TWICE, which is the whole reason bootstrap derives it:
#   - baked into the client as VITE_NOSTR_PUSH_PUBKEY, so clients know where to
#     send their kind-25742 registrations;
#   - set as the relay's MASTER_PUBKEYS, whitelisting the gateway to read the
#     AUTH-gated kinds (4, 1059) it must match against to fire DM push at all.
# If you rotate PUSH_NSEC, rotate both of these with it.
PUSH_NSEC=${PUSH_NSEC}
PUSH_PUBKEY_HEX=${PUSH_PUBKEY_HEX}
# npub form, for pasting into a client. Nothing reads this.
PUSH_NPUB=${PUSH_NPUB}

# ── LiveKit ──────────────────────────────────────────────────────────────────
# Shared between the SFU and the broker that mints tokens for it. Never
# published: Caddy proxies only /rtc, so the server API stays internal.
LIVEKIT_API_KEY=${LIVEKIT_API_KEY}
LIVEKIT_API_SECRET=${LIVEKIT_API_SECRET}

# ── Media ────────────────────────────────────────────────────────────────────
# Blossom's admin dashboard, at ${PUB_SCHEME}://${BLOSSOM_HOST}/admin (user: admin).
BLOSSOM_ADMIN_PASSWORD=${BLOSSOM_ADMIN_PASSWORD}

# ── Push ─────────────────────────────────────────────────────────────────────
# Identifies the push operator to browser push services. VAPID keypairs
# themselves are generated per-domain at runtime and live in the push-storage
# volume; there is nothing to configure here.
VAPID_SUBJECT=mailto:${EMAIL}

# ── Tuning ───────────────────────────────────────────────────────────────────
APP_NAME=Armada
LOG_LEVEL=info

# OpenSearch heap. The single largest memory consumer in the stack.
# Quoted because the value contains a space: Compose's dotenv parser strips the
# quotes, but an unquoted space breaks anyone who \`source\`s this file.
OPENSEARCH_JAVA_OPTS="-Xms1g -Xmx1g"

# Voice token lifetime (seconds); the broker caps this at 86400.
TOKEN_TTL_SECONDS=21600
RATE_LIMIT_PER_MINUTE=60

# Relay kinds gated behind NIP-42. The Armada client is written against this
# exact default (see src/concord/lib/streamAuth.ts) — it authenticates every
# Concord stream pubkey precisely because kind 1059 is listed here.
AUTH_KINDS=4,1059

# Where the client BROADCASTS public notes. Defaults to this stack's own relay
# so nothing leaves the box; set it to a comma-separated list including public
# relays if you want your users' notes to reach the wider network.
BROADCAST_RELAYS=${WS_SCHEME}://${RELAY_HOST}
EOF

chmod 600 "$ENV_FILE"

# ── Report ───────────────────────────────────────────────────────────────────
cat <<EOF

Wrote $ENV_FILE (mode 600)

  client   ${PUB_SCHEME}://${ARMADA_HOST}
  voice    ${PUB_SCHEME}://${AV_HOST}
  relay    ${WS_SCHEME}://${RELAY_HOST}
  media    ${PUB_SCHEME}://${BLOSSOM_HOST}
  push     ${PUSH_NPUB}
           (no hostname — it only makes outbound connections)

Next:
EOF

if [ "$LOCAL" -eq 1 ]; then
  cat <<EOF
  docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build

  Then open ${PUB_SCHEME}://${ARMADA_HOST}. If the name does not resolve, add to
  /etc/hosts:
    127.0.0.1 ${ARMADA_HOST} ${AV_HOST} ${RELAY_HOST} ${BLOSSOM_HOST}
EOF
elif [ -n "$BEHIND_PROXY" ]; then
  cat <<EOF
  1. Point DNS for these four names at your EXISTING public entry point (the
     one that fronts ${BEHIND_PROXY%%/*}) — not at this host directly:
       ${ARMADA_HOST}
       ${AV_HOST}
       ${RELAY_HOST}
       ${BLOSSOM_HOST}

  2. Add a site to that proxy for all four names, forwarding to this host on
     port 80 and PRESERVING THE HOST HEADER — this stack dispatches by Host,
     so one upstream serves all four.

  3. docker compose up -d --build
     (add -f docker-compose.lxc.yml if this is an unprivileged container)

  Voice needs more than HTTP. The SFU's media path is UDP 7882 (and TCP 7881)
  straight to this host; an HTTP reverse proxy cannot carry it, and neither
  can an HTTP-only CDN. Unless those ports are reachable from the internet,
  voice will connect and then carry no audio.
EOF
else
  cat <<EOF
  1. Point DNS at this host — four A/AAAA records:
       ${ARMADA_HOST}
       ${AV_HOST}
       ${RELAY_HOST}
       ${BLOSSOM_HOST}
     Caddy cannot get certificates until these resolve here.

  2. Open the firewall: 80/tcp, 443/tcp, 7881/tcp, 7882/udp.
     7882/udp is the voice media path — voice will connect and then carry no
     audio if it is closed.

  3. docker compose up -d --build
EOF
fi
