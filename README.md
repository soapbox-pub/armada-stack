# armada-stack

A turnkey, self-hosted [Armada](https://gitworkshop.dev/chad@chadwick.site/relay.ngit.dev/armada)
deployment: the client, voice, a relay, push notifications and media, in one
`docker compose up`.

This repo is **glue**. It contains no application source — every image is built
from a sibling checkout.

```
armada-stack/          ← you are here
armada/                ← the client (React + Vite, served by nginx)
armada-av/             ← the blind Concord AV broker (CORD-07 §2)
ditto-relay/           ← the Nostr relay
nostr-push/            ← the Web Push gateway
```

## What you get

| Service | Image | Public address | Notes |
|---|---|---|---|
| `caddy` | `caddy:2-alpine` | 80, 443 | The only published TCP ports. Automatic TLS. |
| `armada` | built from `../armada` | `armada.<domain>` | Static SPA. All config is **baked in at build time**. |
| `broker` | built from `../armada-av` | `av.<domain>` | Mints LiveKit tokens against a self-signed Concord grant. |
| `livekit` | `livekit/livekit-server:v1.8` | `av.<domain>/rtc`, 7881/tcp, 7882/udp | The SFU. Shares an origin with the broker — required. |
| `relay` | built from `../ditto-relay` | `relay.<domain>` | NIPs 1/9/11/13/40/42/45/50/62/70/77. |
| `opensearch` | `opensearchproject/opensearch:2.19.1` | — | Where every event actually lives. |
| `push` | built from `../nostr-push` | — | **No port, no hostname.** Outbound only. |
| `blossom` | `ghcr.io/hzrd149/blossom-server:master` | `blossom.<domain>` | Media uploads. |

## Quick start

```sh
git clone <this repo> armada-stack
cd armada-stack

./scripts/bootstrap.sh --domain example.com --email you@example.com
docker compose up -d --build
```

`bootstrap.sh` runs preflight, generates every secret, derives the values that
must agree across services, and writes `.env`. It never needs a toolchain on
the host — key generation happens in a throwaway container.

You must then:

1. **Point four DNS records at the host** — `armada.`, `av.`, `relay.` and
   `blossom.` Caddy cannot issue certificates until they resolve here.
2. **Open 80/tcp, 443/tcp, 7881/tcp and 7882/udp.** 7882/udp is the voice media
   path; with it closed, voice connects and then carries no audio.

### Trying it without a domain

```sh
./scripts/bootstrap.sh --local
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build
```

Everything runs on `*.localhost` over plain HTTP. Browsers treat `*.localhost`
as a secure context, so microphone access and voice still work.

### Pull mode — no source build for the relay, broker or push

The Quick start builds all four images from sibling checkouts (`../armada`,
`../armada-av`, `../ditto-relay`, `../nostr-push`) plus a Bun toolchain. Pull
mode replaces three of those with a `docker pull` of images published to
[ncontainer.io](https://ncontainer.io) — an OCI registry backed by Nostr +
Blossom, where the image name *is* the publisher's signing identity — leaving
only the client built locally:

```sh
./scripts/bootstrap.sh --domain example.com --email you@example.com --pull
docker compose -f docker-compose.yml -f docker-compose.pull.yml up -d --build armada
```

`--pull` relaxes the preflight sibling check to require only `../armada`. The
client stays a local build because its endpoint URLs are baked into the bundle
at build time from *your* hostnames, so it can't be a pre-published image (see
`docker-compose.pull.yml`); it builds entirely inside its own `node:22-alpine`
stage, so the host needs only Docker and the `../armada` checkout — no Node, no
Bun. Maintainers republish the pulled images with `scripts/publish-images.sh`.

### One-click droplet

`deploy/digitalocean/` has a cloud-init template that provisions the whole
stack in pull mode on a fresh DigitalOcean droplet — you edit two lines
(domain, email), paste it into the droplet's user-data field, and point four
DNS records at the IP. See `deploy/digitalocean/README.md`.

## The three couplings that matter

Most of this stack is ordinary compose. Three values must agree across service
boundaries, and each fails silently rather than loudly if they don't.
`bootstrap.sh` exists mostly to get these right.

**1. The push gateway must be whitelisted on the relay.** The relay gates kinds
4 and 1059 behind NIP-42 (`AUTH_KINDS`). The gateway authenticates as itself,
so by default it can see only its *own* gift wraps — it would match nothing and
DM push would never fire, with no error anywhere. The relay's `MASTER_PUBKEYS`
is set to the gateway's pubkey to grant it read access.

**2. The gateway's pubkey is baked into the client.** `nostr-push` derives its
identity from `NSEC` and only ever prints the pubkey to its own logs. The
client needs it as `VITE_NOSTR_PUSH_PUBKEY` to know where to send kind-25742
registrations. Bootstrap derives it once and uses it in both places.

**3. The client's AV origin must equal the broker's `PUBLIC_ORIGIN`
byte-for-byte.** The client signs a voice grant over that string and the broker
compares it against its own. A mismatch is a 401 on every voice join, and
nothing in either log names the origin as the cause.

## Things worth knowing before you run it

**The client is configured at build time, not runtime.** Every `VITE_*` value
is compiled into the bundle. Changing a domain, the push pubkey or the relay
means `docker compose up -d --build`, not a restart.

**Two host sysctls are not optional.** Neither can be set from compose —
they are host-level, so a container inherits whatever the machine has.
`preflight.sh` checks both:

```sh
# OpenSearch refuses to start below this; the relay then crash-loops on an
# unreachable database.
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-opensearch.conf

# LiveKit's UDP receive buffer. Too small and it drops inbound media under
# load, which users hear as choppy audio rather than seeing as an error.
sudo sysctl -w net.core.rmem_max=5000000
echo 'net.core.rmem_max=5000000' | sudo tee /etc/sysctl.d/99-livekit.conf
```

**OpenSearch is the heavy part.** Budget ~4 GB RAM for the stack; lower
`OPENSEARCH_JAVA_OPTS` in `.env` if that is tight.

**Editing a file under `config/` needs a recreate, not a restart.** They are
bind-mounted individually, and most editors replace a file rather than writing
it in place — which leaves the container holding the old inode and the old
contents. Use `docker compose up -d --force-recreate <service>`.

**Back up `.env`.** `RELAY_NSEC` is the relay's published identity and
`PUSH_NSEC` is the address every client has registered its push subscriptions
against. Neither can be regenerated without consequences. Also back up the
`push-storage` volume: it holds the per-domain VAPID keys, and losing it
invalidates every browser subscription already issued.

**Voice media runs over a bridged UDP port.** That costs some per-packet
overhead versus host networking. If you run enough concurrent voice to feel it:

```sh
docker compose -f docker-compose.yml -f docker-compose.hostnet.yml up -d
```

**Blossom accepts uploads from any Nostr key by default.** A valid Blossom auth
event is required, but anyone can produce one — so on a public hostname it is
an open upload endpoint. To restrict it to your own members, set
`requirePubkeyInRule: true` in `config/blossom/config.yml` and give the storage
rule a `pubkeys:` list.

## Known limits

- **No NIP-29.** ditto-relay does not implement it, so relay-hosted "servers"
  (including Buzz) are not part of this stack. Concord communities — Armada's
  focus — work fully, because Concord is relay-agnostic and needs only an
  ordinary relay that stores kind-1059 and broadcasts kind-21059.
- **iOS push does not deliver.** Armada's iOS build registers as NIP-PUSH
  `type: "apns"`, and `nostr-push` validates APNs config but its `deliverApns`
  is still a stub. Web push works; Android does not use the gateway at all (it
  holds its own relay sockets in a background service).
- **Android and desktop builds are not produced here.** This stack builds the
  web client only. Native builds come from the client repo's own CI.
- **The relay is near-real-time, not immediate.** OpenSearch batches writes and
  refreshes its index on an interval, so an event queried within a second of
  publishing it can legitimately come back empty. This is normal and the client
  does not depend on it being otherwise.

## Layout

```
docker-compose.yml           the stack
docker-compose.local.yml     *.localhost, no TLS
docker-compose.hostnet.yml   SFU on the host network namespace
config/caddy/Caddyfile       routing and TLS for all four hostnames
config/livekit/              SFU config (public and local variants)
config/blossom/config.yml    media server config
images/ditto-relay.Dockerfile  ditto-relay ships none of its own
scripts/bootstrap.sh         writes .env
scripts/preflight.sh         checks the host before you find out the hard way
```

## Operating

```sh
docker compose ps
docker compose logs -f relay
docker compose up -d --build armada     # after changing a VITE_* value
docker compose down                     # keeps volumes
docker compose down -v                  # DESTROYS every event, blob and key
```
