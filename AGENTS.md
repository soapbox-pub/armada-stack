# AGENTS.md

Guidance for agents working on **armada-stack** — the turnkey Docker deployment
of the Armada client, the Concord AV broker, a Nostr relay, a push gateway and
a media server.

**This repo is glue and holds no application source.** The base compose pulls
the relay, broker and push as pinned images off ncontainer.io and builds the
client from a pinned git URL; `docker-compose.dev.yml` swaps all four back to
sibling checkouts (`../armada`, `../armada-av`, `../ditto-relay`,
`../nostr-push`) for working on a component. When something is broken, decide
first whether the bug is in the wiring here or in the component — and if it is
in the component, **fix it there**, in that repo, rather than papering over it
with stack config.

**Never write into the sibling repos from here.** The wiring belongs in this
repo, not in projects with their own release lifecycle: `ditto-relay` is
someone else's project (`gitlab.com/soapbox-pub/ditto-relay`); `armada-av` and
`armada` are ours but release on their own cadence.

## Build / test

There is no test suite. The check that matters is that the thing comes up
healthy:

```sh
./scripts/bootstrap.sh --local              # in a scratch copy; writes COMPOSE_FILE
docker compose config -q                    # syntax + interpolation
docker compose up -d --build --wait         # every service healthy (push: running)
```

`bootstrap.sh` writes `COMPOSE_FILE` into `.env`, so a bare `docker compose`
already includes the right overrides. Verify a change to any override with
`COMPOSE_FILE=docker-compose.yml:<override> docker compose config` — an
override that silently fails to merge produces a working-looking stack in the
wrong configuration. For `docker-compose.dev.yml`, check the four application
services show a `context:` and NO `image:`.

Shell scripts: `bash -n` and `shellcheck -S warning` (the `koalaman/shellcheck`
image works if it is not installed).

## Pins, images, and deploying

**The base `docker-compose.yml` has no local-path dependency — that is its
whole job, and a `../` context in it is a regression.** A fresh server needs
Docker and nothing else.

- **Everything is pinned.** Pulled images by digest (ncontainer images,
  blossom) or exact version (caddy, livekit, opensearch); the client by commit
  in the default of `${ARMADA_BUILD_CONTEXT:-…}`. A stack release is the pins
  moving together in one commit — `update.sh` on a server just follows the
  repo. Never go back to `:latest`/`:master`: servers set up a week apart would
  run different code.
- **The client is NEVER pulled.** Every `VITE_*` is baked into the bundle (see
  *Client config is build-time*), including this deployment's own hostnames,
  so `armada` stays a `build:` from a git-URL context — it compiles inside its
  own `node:22-alpine` stage with only Docker on the host.
- **The client context is the canonical nostr repo's grasp HTTPS endpoint**
  (`https://relay.ngit.dev/<npub>/armada.git#<sha>`), NOT
  `github.com/soapbox-pub/armada`. The GitHub mirror is ~1000 commits stale and
  its Dockerfile predates `VITE_CONCORD_AV_SERVERS` and `VITE_NOSTR_PUSH_*` —
  build args a Dockerfile does not declare are dropped without error, so a
  build from it silently breaks two of the three couplings below.
- **`image: !reset null` in `docker-compose.dev.yml` is load-bearing.** Compose
  MERGES override maps, so a `build:` beside the base's `image:` would build
  and then tag the result with the published ncontainer name.
- **The images identity is permanent-ish, and this repo does not hold it.** The
  npub in the ncontainer refs IS the namespace — a new key is a new set of
  names. It is the SOAPBOX account; each image is signed by its bunker.
  amd64-only by decision.
- **Each component self-publishes its own image; this repo only PULLS them.**
  `armada-av`, `ditto-relay` (→ `armada-relay`) and `nostr-push` (→
  `armada-push`) publish to ncontainer.io from their own ngit-ci job on a push
  to `main`. To ship a component change: push its repo, then bump its digest
  here (`docker pull <ref>:latest` then `docker image inspect --format
  '{{json .RepoDigests}}'`).
- **The stack's own home** is the nostr repo
  `nostr://npub1scvyzz02ayma34hesz62pdrd5nhsmxp74hjq8msmfs9khh3r3drsnw68d8/relay.ngit.dev/armada-stack`,
  cloned by servers over its grasp HTTPS endpoint (no ngit needed). That URL is
  the default `STACK_REPO` in `cloud-init.yml` and `update.sh`.

### Server provisioning (`deploy/`)

- **`deploy/cloud-init/` is provider-generic** and holds the one boot sequence:
  - `cloud-init.yml` — user-data: writes `/etc/armada/deploy.env`, clones
    `STACK_REPO`, runs `install-host.sh`, execs `firstboot.sh`.
  - `install-host.sh` — the host pieces, shared by cloud-init and the Packer
    bake: sysctls (`vm.max_map_count`, `net.core.rmem_max` — host-kernel, not
    settable from compose), ufw, the `armada-firstboot` unit, `armada-setup` +
    its first-login hook, the deploy.env skeleton, the MOTD.
  - `firstboot.sh` — the ONE place the boot sequence lives (self-locating;
    nothing hardcodes `/opt/armada`). Idempotent via
    `/var/lib/armada/.provisioned`; an unconfigured box (placeholders
    unedited) exits 0 without the marker, so the unit retries next boot rather
    than going `failed`. Builds the client BEFORE starting anything (memory),
    then `up --wait`, then reports DNS.
- **`deploy/digitalocean/packer/`** bakes a Marketplace snapshot from a `git
  archive` of HEAD, so `.env`, `backups/` and `.git` never leave the build
  machine; `provision.sh` strips them again anyway. The image has no `.git`;
  `update.sh` adopts the published repo in place on first update.
- DNS is manual on every path: four records must point at the IP before Caddy
  can get certs. `scripts/check-dns.sh` reports; nothing blocks on it.

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
registered against. `scripts/backup.sh` covers all five (`--quick`: the three
small ones, live); a new irreplaceable volume must be added there too.

Blossom's upstream `config.example.yml` ships retention rules that **delete**
blobs after 2 days to 1 month; `config/blossom/config.yml` sets 10 years
instead. On a chat deployment the upstream defaults mean images silently
vanishing out of history while the messages referencing them remain. Don't
"restore the defaults" when syncing that file with upstream.

## Version pins that are not independent

- **`livekit/livekit-server` must be >= the `livekit-client` at the pinned
  client ref** (its `package.json`/lockfile, not necessarily `../armada`'s
  working tree). Signaling protocol skew makes clients full-reconnect roughly
  every 16 seconds. Bumping the client pin to a newer SDK means bumping the
  image here in the same commit.
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
