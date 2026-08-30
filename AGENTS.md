# AGENTS.md

Guidance for agents working on **armada-stack** — the turnkey Docker deployment
of the Armada client, the Concord AV broker, a Nostr relay, a push gateway and
a media server.

**This repo is glue and holds no application source.** By default every image is
built from a sibling checkout: `../armada`, `../armada-av`, `../ditto-relay`,
`../nostr-push`. When something is broken, decide first whether the bug is in
the wiring here or in the component — and if it is in the component, **fix it
there**, in that repo, rather than papering over it with stack config. (Pull
mode swaps three of those source builds for pre-built images off ncontainer.io;
see *Pull mode* below. The client is always a local build.)

**Never write into the sibling repos from here.** `ditto-relay` ships no
Dockerfile, and the fix was `images/ditto-relay.Dockerfile` in THIS repo fed by
a named BuildKit context, not a Dockerfile committed upstream. `ditto-relay` is
someone else's project (`gitlab.com/soapbox-pub/ditto-relay`); `armada-av` and
`armada` are ours but have their own release lifecycle.

## Build / test

There is no test suite. The check that matters is that the thing comes up:

```sh
./scripts/preflight.sh
docker compose config -q                    # syntax + interpolation
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build
docker compose ps                           # every service should stay up
```

`docker compose config -q` needs a `.env`; run `./scripts/bootstrap.sh --local`
first, in a scratch copy if you don't want to touch a real one.

Verify a change to `docker-compose.hostnet.yml` or `docker-compose.local.yml`
with `docker compose -f docker-compose.yml -f <override> config` — an override
that silently fails to merge produces a working-looking stack in the wrong
configuration.

## Pull mode, publishing images, and the droplet

`docker-compose.pull.yml` overrides `relay`, `broker` and `push` to a
`docker pull` from **ncontainer.io** — an OCI registry backed by Nostr (a signed
kind-30624 event holds the tag→digest map) + Blossom (the layer blobs), where
the image NAME is the publisher's signing identity (`../ncontainer`). It exists
so a self-hoster needs neither those three source trees nor a Bun toolchain: the
stack pulls them. The point is to make self-hosting easier, so keep it that way.

- **The client is NEVER pulled.** Every `VITE_*` is baked into the bundle at
  build time (see *Client config is build-time*), and those values include this
  deployment's own hostnames — which a pre-published image cannot know. So
  `armada` stays the base file's local build, and `up` in pull mode is
  `... -f docker-compose.pull.yml up -d --build armada`: pull the three, build
  the one. It builds inside its own `node:22-alpine` stage, so the host needs
  only Docker + `../armada`.
- **The `!reset null` on `build:` is load-bearing.** Compose MERGES override
  maps into the base, so adding `image:` beside the inherited `build:` leaves
  both set and Compose builds-and-tags instead of pulling. `!reset null` drops
  the build block. Verify with `docker compose -f docker-compose.yml -f
  docker-compose.pull.yml config` and check the three show `image:` and NO
  `build:`.
- **The images identity is permanent-ish.** The npub hardcoded in
  `docker-compose.pull.yml` (and the deploy docs) IS the namespace — a new key
  is a new set of names and a stack-wide reference change. The nsec lives in
  `.images.env` (gitignored, like `.env`); losing it means the three names can
  never be republished. amd64-only by decision.
- **`scripts/publish-images.sh` is a MAINTAINER tool, not part of any deploy.**
  Without `--dry-run` it uploads layer blobs to public Blossom servers and signs
  public events under the images identity. It builds each image to an OCI layout
  via an ephemeral `docker-container` buildx builder (the default `docker`
  driver can't use the OCI exporter), then runs ncontainer's own `upload.ts` /
  `publish.ts` in an `oven/bun:1` container — no host toolchain, same principle
  as `bootstrap.sh`. `--provenance=false --sbom=false` is required: an
  attestation manifest turns the export into a list with an `unknown/unknown`
  entry that `publish.ts` would mint a bogus tag for. `BLOSSOM_SERVERS` has no
  default — a container layer is a large octet-stream blob and media-oriented
  Blossom servers answer 415.
- **`--pull` on `bootstrap.sh`/`preflight.sh`** relaxes the sibling check to
  require only `../armada` (the one still built locally). `bootstrap.sh`
  forwards it to preflight.
- **The droplet** (`deploy/digitalocean/`) is a cloud-init template that
  provisions the whole stack in pull mode: installs Docker, sets the two host
  sysctls (`vm.max_map_count`, `net.core.rmem_max` — host-kernel, not settable
  from compose), opens the firewall, clones the stack + `../armada`, and runs
  bootstrap+up. It is guarded by a done-marker so a re-run is idempotent.
  `STACK_REPO` has NO default because armada-stack is not yet published to any
  git host — that is a real dependency, not an oversight. DNS is still manual:
  four records must point at the IP before Caddy can get certs, and no provider
  button creates records in a domain registered elsewhere.

## The couplings — do not break these

Three values cross service boundaries, and every one of them fails **silently**.
None will show up in a log. `scripts/bootstrap.sh` is the single place they are
derived, which is the point: they are not three settings, they are one.

- **`MASTER_PUBKEYS` (relay) = the pubkey of `PUSH_NSEC` (gateway).** The relay
  gates kinds 4 and 1059 behind NIP-42. The gateway authenticates as itself, so
  without the whitelist it can read only its own gift wraps, matches nothing,
  and DM push never fires. Nothing errors — there is simply never a
  notification.
- **`VITE_NOSTR_PUSH_PUBKEY` (client) = the same pubkey.** The gateway
  publishes no announcement of any kind; its identity is printed to its own log
  and nowhere else. If these disagree, clients send kind-25742 registrations
  addressed to a pubkey no one is listening on.
- **`VITE_CONCORD_AV_SERVERS` (client) = `PUBLIC_ORIGIN` (broker), byte for
  byte.** The client signs a kind-27235 grant over that string; the broker
  compares it to its own. A trailing slash, a `www.`, or http-vs-https is a 401
  on every voice join with nothing naming the origin.

A fourth is a deployment choice often mistaken for a requirement: **the broker
and the SFU are co-located, but need not be.** The broker returns the SFU's URL
(`LIVEKIT_WS_URL`) to the client, and that may point at any SFU — it is
independent of the broker's own `PUBLIC_ORIGIN`, which only has to match what
the client signed its grant over. Co-locating them is why
`config/caddy/Caddyfile` routes `/rtc` and `/.well-known/concord/av*` on one
site block, and it is the right default; but when the host has no public UDP
path for media, pointing `LIVEKIT_WS_URL` at an SFU that does is a supported
configuration, not a hack. What is genuinely fixed is that the URL must be a
BARE ORIGIN, since the SDK appends `/rtc` to it.

## Proxy headers: the two components disagree, on purpose

- **armada-av reads the RIGHTMOST `X-Forwarded-For` entry** — the peer it was
  handed by, which is unforgeable. Caddy appends, so plain XFF is correct and
  `TRUST_PROXY: "1"` is safe.
- **ditto-relay reads the LEFTMOST entry** of whatever `IP_HEADER` names. On
  Caddy's appended XFF the leftmost entry is **client-supplied**, so pointing
  `IP_HEADER` at `X-Forwarded-For` hands every client control of its own rate
  limit key. The Caddyfile sets `X-Real-IP` with `header_up`, which REPLACES,
  and `IP_HEADER` names that.

Don't "simplify" these to match each other. They are reading different headers
because they parse them differently.

## Ports and networking

Everything is on one bridge network; only `caddy` (80/443) and `livekit`
(7881/tcp, 7882/udp) publish. That is load-bearing for the broker: `TRUST_PROXY`
is only safe because port 8080 is unreachable from outside the network. **If you
publish the broker, turn `TRUST_PROXY` off in the same commit.**

LiveKit's 7880 is deliberately unpublished — it carries both signal and the
Twirp server API, which can create and destroy any room. Caddy proxies only
`/rtc`, so `/twirp` exists solely on the internal network. Don't add a
catch-all `reverse_proxy` to the `av.` site block.

`use_external_ip` differs between `livekit.yaml` (true) and
`livekit.local.yaml` (false), and that is the entire reason two files exist. On
a laptop, true makes LiveKit STUN-discover the machine's public address and
advertise it in ICE candidates, which the local browser cannot reach — voice
negotiates and then carries no media.

## Client config is build-time

Every `VITE_*` is a build ARG compiled into the bundle. There is no runtime
config file to edit and no environment variable to restart into. A change to
any `*_SITE`, `RELAY_WS_URL` or `PUSH_PUBKEY_HEX` in `.env` requires
`docker compose up -d --build armada`; a plain `restart` will appear to work
and serve the old values.

The client's own `nginx.conf` already owns cache policy, CSP and the SPA
fallback. Don't restate any of it in the Caddyfile — that would be a second
copy that drifts, and Caddy sits in front of nginx, not instead of it.

## Storage and what cannot be regenerated

| Volume | Holds | If lost |
|---|---|---|
| `opensearch-data` | every event on the relay | the relay's entire history |
| `push-storage` | per-domain VAPID keypairs | **every existing browser subscription is invalidated** — `applicationServerKey` was bound to the old key |
| `blossom-data` | uploaded blobs + sqlite index | all media |
| `caddy-data` | ACME account key + certificates | re-issues everything, into Let's Encrypt's duplicate-cert rate limit |

`.env` is not a volume but belongs on this list: `RELAY_NSEC` is the relay's
published identity and `PUSH_NSEC` is the address every client has already
registered against.

Blossom's upstream `config.example.yml` ships retention rules that **delete**
blobs after 2 days to 1 month; `config/blossom/config.yml` sets 10 years
instead. On a chat deployment the upstream defaults mean images silently
vanishing out of history while the messages referencing them remain. Don't
"restore the defaults" when syncing that file with upstream.

## Version pins that are not independent

- **`livekit/livekit-server` must be >= the `livekit-client` in
  `../armada/package.json`.** Signaling protocol skew makes clients
  full-reconnect roughly every 16 seconds. Bumping the client's SDK means
  bumping the image here.
- **`oven/bun:1`** in `images/ditto-relay.Dockerfile` matches what ditto-relay's
  own CI runs. It cannot be Node: `src/server.ts` imports `serve` from `"bun"`,
  uses `server.requestIP()`, and spawns Workers with the Bun-only `smol`
  option.
- **`nostr-tools` in `scripts/lib/keygen.ts` is pinned**, not floating. It mints
  the stack's long-lived identities from a package fetched at bootstrap time.

## Relay behaviour the client depends on

The Armada client is written against ditto-relay specifically — see
`../armada/src/concord/lib/streamAuth.ts`, which names `AUTH_KINDS=4,1059` by
name and authenticates every Concord stream pubkey because of it. Consequences:

- Concord rides kind **1059** (durable wraps) and **21059** (ephemeral: typing,
  voice presence, realtime frames). Ephemeral kinds are broadcast and not
  stored, which is correct and must stay that way.
- The relay's default `REJECTED_KINDS` includes **20013/20014**, the Concord
  seals. That is right: seals only ever ride *inside* a wrap, and a standalone
  one is not a thing Armada publishes. Don't remove them from the list.
- Changing `AUTH_KINDS` to drop 1059 would make Concord reads work without
  AUTH, which sounds like a simplification and is actually a privacy
  regression.

## Conventions

- Commit messages: concise, imperative, sentence case. Describe the technical
  change; don't assert a root-cause narrative.
- Never commit `.env`, secrets, or anything derived from a real deployment's
  keys.
- Always run `docker compose config -q` before committing a compose change.
- Comments in the compose and config files explain **why**, because the values
  themselves are mostly self-evident and the reasons are not. Keep that.
