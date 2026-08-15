# AGENTS.md

Guidance for agents working on **armada-stack** — the turnkey Docker deployment
of the Armada client, the Concord AV broker, a Nostr relay, a push gateway and
a media server.

**This repo is glue and holds no application source.** Every image is built
from a sibling checkout: `../armada`, `../armada-av`, `../ditto-relay`,
`../nostr-push`. When something is broken, decide first whether the bug is in
the wiring here or in the component — and if it is in the component, **fix it
there**, in that repo, rather than papering over it with stack config.

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

A fourth is structural rather than a value: **the broker and the SFU must share
one origin.** The broker returns a bare `wss://` URL and the LiveKit SDK
appends `/rtc` itself, so the signal socket lands back on the broker's own
hostname. That is why `config/caddy/Caddyfile` routes `/rtc` and
`/.well-known/concord/av*` on the same site block. Splitting them onto two
hostnames cannot be made to work by configuration.

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
