# armada-stack

A turnkey, self-hosted [Armada](https://gitworkshop.dev/chad@chadwick.site/relay.ngit.dev/armada)
deployment: the client, voice, a relay, push notifications and media, in one
`docker compose up`.

This repo is **glue**. It contains no application source: the relay, voice
broker and push gateway are pulled as pinned, signed images from
[ncontainer.io](https://ncontainer.io), and the client is built from a pinned
git URL. A server needs Docker and nothing else.

## What you get

| Service | Image | Public address | Notes |
|---|---|---|---|
| `caddy` | `caddy:2.11.4-alpine` | 80, 443 | The only published TCP ports. Automatic TLS. |
| `armada` | built from a pinned git ref | `armada.<domain>` | Static SPA. All config is **baked in at build time**. |
| `broker` | `ncontainer.io/…/armada-av` | `av.<domain>` | Mints LiveKit tokens against a self-signed Concord grant. |
| `livekit` | `livekit/livekit-server:v1.13.7` | `av.<domain>/rtc`, 7881/tcp, 7882/udp | The SFU. Shares an origin with the broker by default. |
| `relay` | `ncontainer.io/…/armada-relay` | `relay.<domain>` | ditto-relay. NIPs 1/9/11/13/40/42/45/50/62/70/77. |
| `opensearch` | `opensearchproject/opensearch:2.19.1` | — | Where every event actually lives. |
| `push` | `ncontainer.io/…/armada-push` | — | nostr-push. **No port, no hostname.** Outbound only. |
| `blossom` | `ghcr.io/hzrd149/blossom-server` (pinned digest) | `blossom.<domain>` | Media uploads. |

Every image is pinned by digest or exact version, and so is the client's git
ref. A stack release is those pins moving together in one commit.

## Deploy on a server — one paste

Any provider that takes cloud-init user-data (DigitalOcean, Hetzner, Vultr,
Linode, Lightsail, …): create an **Ubuntu 24.04** server with **4 GB RAM**, and
paste [`deploy/cloud-init/cloud-init.yml`](deploy/cloud-init/cloud-init.yml)
into its user-data field with `DOMAIN` and `EMAIL` edited. Leave them as
placeholders and the server waits instead; SSH in and `armada-setup` asks for
them.

Then **point four DNS records at the server's IP** — `armada.`, `av.`,
`relay.` and `blossom.` under your domain. Caddy cannot issue certificates
until they resolve. `/opt/armada/stack/scripts/check-dns.sh` shows where each
one stands; progress is in `/var/log/armada-firstboot.log`.

First boot installs Docker, sets the host sysctls and firewall, generates every
secret, builds the client (the slow part: a few minutes) and waits for every
service to report healthy.

For a DigitalOcean Marketplace-style image with all of that pre-baked, see
[`deploy/digitalocean/`](deploy/digitalocean/README.md).

## Deploy by hand

```sh
git clone https://relay.ngit.dev/npub1scvyzz02ayma34hesz62pdrd5nhsmxp74hjq8msmfs9khh3r3drsnw68d8/armada-stack.git
cd armada-stack

./scripts/bootstrap.sh --domain example.com --email you@example.com
docker compose up -d --build
```

`bootstrap.sh` runs preflight, generates every secret, derives the values that
must agree across services, and writes `.env` — including `COMPOSE_FILE`, so
every later command in every mode is a bare `docker compose`. It never needs a
toolchain on the host: key generation happens in a throwaway container.

You must then:

1. **Point four DNS records at the host** — `armada.`, `av.`, `relay.` and
   `blossom.` Caddy cannot issue certificates until they resolve here.
   `./scripts/check-dns.sh` checks.
2. **Open 80/tcp, 443/tcp, 443/udp, 7881/tcp and 7882/udp.** 7882/udp is the
   voice media path; with it closed, voice connects and then carries no audio.

### Trying it without a domain

```sh
./scripts/bootstrap.sh --local
docker compose up -d --build
```

Everything runs on `*.localhost` over plain HTTP. Browsers treat `*.localhost`
as a secure context, so microphone access and voice still work.

### Developing a component against the stack

```sh
./scripts/bootstrap.sh --local --dev
docker compose up -d --build
```

`--dev` adds `docker-compose.dev.yml`, which builds all four application images
from sibling checkouts — `../armada`, `../armada-av`, `../ditto-relay`,
`../nostr-push` — instead of pulling them. Never deploy with it.

### Pinning a different client

The client ref is pinned in `docker-compose.yml`. To build something else, set
in `.env`:

```sh
ARMADA_BUILD_CONTEXT=https://relay.ngit.dev/<npub>/armada.git#<tag|branch|sha>
```

then `docker compose up -d --build armada`.

## Operating

```sh
./scripts/update.sh          # to the latest stack release; backs up first
./scripts/backup.sh          # everything irreplaceable (brief relay downtime)
./scripts/backup.sh --quick  # secrets, push keys, certs only — live-safe
./scripts/check-dns.sh       # do the four names resolve here?

docker compose ps
docker compose logs -f relay
docker compose up -d --build armada     # after changing a VITE_* value
docker compose down                     # keeps volumes
docker compose down -v                  # DESTROYS every event, blob and key
```

Copy backups **off** the server; `backup.sh` explains restore in its header.

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
invalidates every browser subscription already issued. `scripts/backup.sh`
takes both.

**Voice media runs over a bridged UDP port.** That costs some per-packet
overhead versus host networking. If you run enough concurrent voice to feel it,
append `:docker-compose.hostnet.yml` to `COMPOSE_FILE` in `.env`, then
`docker compose up -d`.

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
docker-compose.yml           the stack: pinned images + the client's git ref
docker-compose.local.yml     *.localhost, no TLS
docker-compose.dev.yml       build from sibling checkouts instead of pulling
docker-compose.hostnet.yml   SFU on the host network namespace
docker-compose.lxc.yml       unprivileged containers (added automatically)
config/caddy/Caddyfile       routing and TLS for all four hostnames
config/livekit/              SFU config (public and local variants)
config/blossom/config.yml    media server config
scripts/bootstrap.sh         writes .env
scripts/preflight.sh         checks the host before you find out the hard way
scripts/check-dns.sh         do the four names resolve here?
scripts/update.sh            move to the latest stack release
scripts/backup.sh            archive everything irreplaceable
deploy/cloud-init/           user-data, first boot and host setup for any VPS
deploy/digitalocean/         Packer image for a Marketplace 1-Click
```
