#!/usr/bin/env bash
# Build the centrally-published stack images and publish them to ncontainer.io.
#
#   ./scripts/publish-images.sh            build + upload + sign all
#   ./scripts/publish-images.sh --dry-run  build + export + tag-map only; no writes
#   ./scripts/publish-images.sh relay      just one (relay | push)
#
# This covers the components that are NOT their own nostr repo: the relay (from
# ../ditto-relay, gitlab-only) and push (from ../nostr-push, gitlab-only). The
# broker is armada-av, which is a nostr repo and self-publishes its own image
# from its own CI — see docker-compose.pull.yml's broker note. Add each of the
# other two here only until they too carry the drop-in.
#
# ncontainer has no `docker push` and no account: an OCI image is already a
# content-addressed blob graph, so "publishing" is (see ../ncontainer/README):
#   1. export each image as an OCI layout (a directory of blobs named by sha256),
#   2. upload those blobs to Blossom (BUD-02, a signed kind-24242 auth), and
#   3. sign one kind-30624 event per repo mapping `latest` -> the manifest digest.
# The image NAME is the signing key's npub, so each name always resolves to this
# identity's builds and nobody else's.
#
# SIGNING IS THROUGH nak, so the signer can be a raw key OR a NIP-46 bunker.
# That is the whole point: CI signs as the soapbox account through its bunker,
# with no raw nsec ever on the runner. Signer config comes from the environment
# (CI injects it) or, for a local run, from .images.env sourced beside this file:
#
#   IMAGES_SIGNER      an nsec / ncryptsec / hex key, OR a bunker:// URL
#   IMAGES_CONNECT_AS  (bunker only) the client key nak connects to the bunker as
#   IMAGES_NPUB        the namespace npub — OUTPUT ONLY, and a guard: it must be
#                      the pubkey the signer actually signs as, or the published
#                      names will not be what this prints
#   PUBLISH_RELAYS     comma-separated relays the kind-30624 events go to
#   BLOSSOM_SERVERS    comma-separated Blossom servers the LAYERS upload to. No
#                      default: a container layer is a large octet-stream blob
#                      and media-oriented servers (e.g. blossom.band) answer 415
#
# The host needs Docker, nak and node. CI provides all three; a local maintainer
# installs nak (github.com/fiatjaf/nak) and has node from the armada checkout.
#
# THIS IS AN OUTWARD-FACING ACTION. Without --dry-run it uploads blobs to public
# Blossom servers and publishes signed events to public relays under the signing
# identity. It is a MAINTAINER / CI tool, not part of any deploy.
set -euo pipefail

STACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGES_ENV="$STACK_DIR/.images.env"
OCI_TAGS="$STACK_DIR/scripts/lib/oci-tags.mjs"

BUILDER="armada-oci-publish"
DRY_RUN=0
ONLY=""

die() { printf '\033[31merror\033[0m %s\n' "$*" >&2; exit 1; }
say() { printf '\033[36m==>\033[0m %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    relay|push) ONLY="$1"; shift ;;
    -h|--help) sed -n '2,38p' "$0"; exit 0 ;;
    *) die "unknown argument: $1 (expected --dry-run or one of relay|push)" ;;
  esac
done

# ── Preconditions ────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || die "docker not found on PATH"
docker info >/dev/null 2>&1 || die "the docker daemon is not reachable"
command -v node  >/dev/null 2>&1 || die "node not found on PATH (needed for scripts/lib/oci-tags.mjs)"
[ -f "$OCI_TAGS" ] || die "missing $OCI_TAGS"

# A local run keeps its signer config in .images.env; CI puts the same names in
# the environment, so only source the file when it exists.
if [ -f "$IMAGES_ENV" ]; then
  # shellcheck disable=SC1090
  . "$IMAGES_ENV"
fi

: "${IMAGES_SIGNER:?set IMAGES_SIGNER (an nsec or a bunker:// URL) in .images.env or the environment}"
: "${IMAGES_NPUB:?set IMAGES_NPUB (the namespace npub) in .images.env or the environment}"

if [ "$DRY_RUN" -ne 1 ]; then
  command -v nak >/dev/null 2>&1 || die "nak not found on PATH (needed to sign; github.com/fiatjaf/nak)"
  : "${PUBLISH_RELAYS:?set PUBLISH_RELAYS in .images.env or the environment}"
  [ -n "${BLOSSOM_SERVERS:-}" ] || die \
"BLOSSOM_SERVERS is empty. A container layer is a large octet-stream blob and
       media-oriented Blossom servers reject it (415). Set it to one or more
       servers that accept large octet-stream uploads, or pass --dry-run."

  # Fail fast if the signer does not actually sign as IMAGES_NPUB — otherwise the
  # events publish under one pubkey while the compose refs name another, and the
  # stack silently pulls from a namespace nothing was published to.
  signer_hex="$(nak key public "$IMAGES_SIGNER" 2>/dev/null || true)"
  # A bunker can't be introspected offline; only check when the signer is a key.
  if [ -n "$signer_hex" ]; then
    want_hex="$(nak decode "$IMAGES_NPUB" 2>/dev/null | grep -oiE '[0-9a-f]{64}' | head -1 || true)"
    [ "$signer_hex" = "$want_hex" ] || die \
      "IMAGES_SIGNER signs as $signer_hex but IMAGES_NPUB is $want_hex — they must match."
  fi
fi

# nak signer flags, shared by the blossom upload (24242) and the event (30624).
# --connect-as is only meaningful for a bunker signer.
nak_signer() {
  printf '%s\0' --sec "$IMAGES_SIGNER"
  [ -n "${IMAGES_CONNECT_AS:-}" ] && printf '%s\0' --connect-as "$IMAGES_CONNECT_AS"
}

# Each image: <repo-name> then the buildx context arguments. The relay reuses
# images/ditto-relay.Dockerfile with the relay source as a named build context —
# exactly as docker-compose.yml builds it; push carries its own Dockerfile.
#
# The broker is deliberately NOT here. armada-av publishes its own image (name
# `armada-av`, matching the compose ref) from its own ngit-repo CI
# (its scripts/publish-container.sh), so building it here too would be a second
# publisher minting a different name under the same identity.
build_args_for() {
  case "$1" in
    relay)  printf '%s\n' "armada-relay" \
              "-f" "images/ditto-relay.Dockerfile" \
              "--build-context" "relay-src=../ditto-relay" "." ;;
    push)   printf '%s\n' "armada-push" "../nostr-push" ;;
    *) die "unknown image key: $1" ;;
  esac
}

# ── Ephemeral OCI-capable builder ────────────────────────────────────────────
# The default `docker` driver cannot use the OCI exporter; a `docker-container`
# builder can. Created here and torn down on exit so we leave no state behind.
WORK=""
cleanup() {
  docker buildx rm "$BUILDER" >/dev/null 2>&1 || true
  [ -n "$WORK" ] && rm -rf "$WORK"
}
trap cleanup EXIT
docker buildx inspect "$BUILDER" >/dev/null 2>&1 || \
  docker buildx create --name "$BUILDER" --driver docker-container >/dev/null
WORK="$(mktemp -d)"

publish_one() {
  local key="$1"
  local repo
  mapfile -t spec < <(build_args_for "$key")
  repo="${spec[0]}"
  local context=("${spec[@]:1}")

  local layout="$WORK/$key"
  mkdir -p "$layout"

  say "build $repo (linux/amd64) -> OCI layout"
  # --provenance/--sbom off: an attestation manifest turns the export into a
  # manifest list with an unknown/unknown entry, which would mint a bogus tag.
  # amd64-only, per the decision on architectures.
  docker buildx build --builder "$BUILDER" --platform linux/amd64 \
    --provenance=false --sbom=false \
    -t "$repo:latest" \
    "${context[@]}" \
    --output "type=oci,tar=false,dest=$layout" \
    >/dev/null

  # Extract the tag->digest map (and write the synthesized index blob into the
  # layout). Stdout is the JSON contract; diagnostics are on stderr.
  local tags_json
  tags_json="$(node "$OCI_TAGS" "$layout")"

  if [ "$DRY_RUN" -eq 1 ]; then
    say "dry-run: $repo exported to $layout ($(du -sh "$layout" | cut -f1))"
    printf '    tags: %s\n' "$tags_json"
    return
  fi

  # Upload every blob (manifests, config, layers, the synthesized index) to each
  # Blossom server. nak blossom signs a kind-24242 auth with the same signer.
  local server
  IFS=',' read -ra servers <<< "$BLOSSOM_SERVERS"
  for server in "${servers[@]}"; do
    server="$(printf '%s' "$server" | tr -d '[:space:]')"
    [ -n "$server" ] || continue
    say "upload $repo blobs -> $server"
    # shellcheck disable=SC2046
    mapfile -d '' -t signer < <(nak_signer)
    nak blossom -s "$server" "${signer[@]}" upload "$layout"/blobs/sha256/* >/dev/null
  done

  # Build the kind-30624 tag arguments from the JSON, then sign+publish.
  local -a evt_tags
  evt_tags=(-d "$repo" -t "title=$repo")
  while IFS=$'\t' read -r name digest; do
    evt_tags+=(-t "tag=${name};${digest}")
  done < <(node -e 'const j=JSON.parse(require("fs").readFileSync(0,"utf8"));for(const[n,d]of j.tags)process.stdout.write(n+"\t"+d+"\n")' <<<"$tags_json")
  for server in "${servers[@]}"; do
    server="$(printf '%s' "$server" | tr -d '[:space:]')"
    [ -n "$server" ] && evt_tags+=(-t "server=$server")
  done

  say "sign $repo repository event -> $PUBLISH_RELAYS"
  IFS=',' read -ra relays <<< "$PUBLISH_RELAYS"
  mapfile -d '' -t signer < <(nak_signer)
  nak event -k 30624 "${evt_tags[@]}" -c '' "${signer[@]}" "${relays[@]}" >/dev/null
  printf '\033[32m    ncontainer.io/%s/%s:latest\033[0m\n' "$IMAGES_NPUB" "$repo"
}

if [ -n "$ONLY" ]; then
  publish_one "$ONLY"
else
  for key in relay push; do publish_one "$key"; done
fi

say "done"
