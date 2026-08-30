#!/usr/bin/env bash
# Build the three pull-able stack images and publish them to ncontainer.io.
#
#   ./scripts/publish-images.sh            build + upload + sign all three
#   ./scripts/publish-images.sh --dry-run  build + export only; no network writes
#   ./scripts/publish-images.sh relay      just one (relay | broker | push)
#
# What "publish" means here is ncontainer's two-step (see ../ncontainer/README):
# an OCI image is already a content-addressed blob graph, so we
#   1. export each image as an OCI layout (a directory of blobs named by sha256),
#   2. upload those blobs to Blossom (BUD-02), and
#   3. sign one kind-30624 event per repo mapping `latest` -> the manifest digest.
# There is no `docker push` and no registry account: the image NAME is the
# signing key (IMAGES_NSEC), which is why the same three names always resolve to
# our builds and to nobody else's.
#
# The host needs only Docker. The OCI export runs in an ephemeral
# `docker-container` buildx builder; the upload/sign step runs ncontainer's own
# TypeScript in a throwaway `oven/bun:1` container. No Node, no Bun, no toolchain
# on the host — the same principle as bootstrap.sh.
#
# THIS IS AN OUTWARD-FACING ACTION. Without --dry-run it uploads blobs to public
# Blossom servers and publishes signed events to public relays under the images
# identity. It is a MAINTAINER tool, not part of any deploy.
set -euo pipefail

STACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGES_ENV="$STACK_DIR/.images.env"

# ncontainer is a sibling checkout, like ../armada and ../ditto-relay. Override
# with NCONTAINER_DIR if you keep it elsewhere.
NCONTAINER_DIR="${NCONTAINER_DIR:-$STACK_DIR/../ncontainer}"

BUILDER="armada-oci-publish"
DRY_RUN=0
ONLY=""

die() { printf '\033[31merror\033[0m %s\n' "$*" >&2; exit 1; }
say() { printf '\033[36m==>\033[0m %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    relay|broker|push) ONLY="$1"; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) die "unknown argument: $1 (expected --dry-run or one of relay|broker|push)" ;;
  esac
done

# ── Preconditions ────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || die "docker not found on PATH"
docker info >/dev/null 2>&1 || die "the docker daemon is not reachable"

[ -f "$IMAGES_ENV" ] || die ".images.env not found. It carries IMAGES_NSEC — see the file's header."
# shellcheck disable=SC1090
. "$IMAGES_ENV"
: "${IMAGES_NSEC:?.images.env has no IMAGES_NSEC}"
: "${IMAGES_NPUB:?.images.env has no IMAGES_NPUB}"

if [ "$DRY_RUN" -ne 1 ]; then
  : "${PUBLISH_RELAYS:?.images.env has no PUBLISH_RELAYS}"
  [ -n "${BLOSSOM_SERVERS:-}" ] || die \
"BLOSSOM_SERVERS is empty in .images.env. A container layer is a large
       octet-stream blob and media-oriented Blossom servers reject it (415).
       Set BLOSSOM_SERVERS to one or more you control/trust, or pass --dry-run."
  [ -d "$NCONTAINER_DIR/scripts" ] || die \
"ncontainer not found at $NCONTAINER_DIR (needed for upload.ts/publish.ts).
       Clone it beside the stack, or set NCONTAINER_DIR:
         git clone nostr://alex@gleasonator.com/relay.ngit.dev/ncontainer ../ncontainer"
fi

# Each image: <key> <repo-name> then the buildx context arguments. The relay has
# no Dockerfile of its own, so it reuses images/ditto-relay.Dockerfile with the
# relay source wired in as a named build context — exactly as docker-compose.yml
# builds it. broker and push each carry their own Dockerfile.
build_args_for() {
  case "$1" in
    relay)  printf '%s\n' "armada-relay" \
              "-f" "images/ditto-relay.Dockerfile" \
              "--build-context" "relay-src=../ditto-relay" "." ;;
    broker) printf '%s\n' "armada-broker" "../armada-av" ;;
    push)   printf '%s\n' "armada-push" "../nostr-push" ;;
    *) die "unknown image key: $1" ;;
  esac
}

# ── Ephemeral OCI-capable builder ────────────────────────────────────────────
# The default `docker` driver cannot use the OCI exporter; a `docker-container`
# builder can. Created here and torn down on exit so we leave no state behind.
cleanup() { docker buildx rm "$BUILDER" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker buildx inspect "$BUILDER" >/dev/null 2>&1 || \
  docker buildx create --name "$BUILDER" --driver docker-container >/dev/null

WORK="$(mktemp -d)"
trap 'cleanup; rm -rf "$WORK"' EXIT

# Run one of ncontainer's scripts inside oven/bun:1, with ncontainer mounted for
# its source (and node_modules cache) and the layout mounted read-write, since
# publish.ts writes a synthesized index blob back into it.
nc_run() {
  local script="$1"; shift
  docker run --rm \
    -v "$NCONTAINER_DIR":/nc \
    -v "$LAYOUT":/layout \
    -w /nc \
    oven/bun:1 \
    sh -c "bun install --frozen-lockfile >/dev/null 2>&1 && bun run scripts/$script \"\$@\"" \
    _ "$@"
}

publish_one() {
  local key="$1"
  local repo context
  mapfile -t spec < <(build_args_for "$key")
  repo="${spec[0]}"
  context=("${spec[@]:1}")

  LAYOUT="$WORK/$key"
  mkdir -p "$LAYOUT"

  say "build $repo (linux/amd64) -> OCI layout"
  # --provenance/--sbom off: an attestation manifest turns the export into a
  # manifest list with an unknown/unknown entry, which publish.ts would mint a
  # bogus tag for. amd64-only, per the decision on architectures.
  docker buildx build --builder "$BUILDER" --platform linux/amd64 \
    --provenance=false --sbom=false \
    -t "$repo:latest" \
    "${context[@]}" \
    --output "type=oci,tar=false,dest=$LAYOUT" \
    >/dev/null

  if [ "$DRY_RUN" -eq 1 ]; then
    say "dry-run: $repo exported to $LAYOUT ($(du -sh "$LAYOUT" | cut -f1)); not uploading or signing"
    return
  fi

  # Upload takes ONE server per call; loop the list so every layer lands on each.
  local server
  IFS=',' read -ra servers <<< "$BLOSSOM_SERVERS"
  for server in "${servers[@]}"; do
    server="$(printf '%s' "$server" | tr -d '[:space:]')"
    [ -n "$server" ] || continue
    say "upload $repo blobs -> $server"
    nc_run upload.ts /layout "$IMAGES_NSEC" "$server"
  done

  say "sign $repo repository event -> $PUBLISH_RELAYS"
  nc_run publish.ts /layout "$repo" "$IMAGES_NSEC" "$PUBLISH_RELAYS" "$BLOSSOM_SERVERS"
  printf '\033[32m    ncontainer.io/%s/%s:latest\033[0m\n' "$IMAGES_NPUB" "$repo"
}

if [ -n "$ONLY" ]; then
  publish_one "$ONLY"
else
  for key in relay broker push; do publish_one "$key"; done
fi

say "done"
