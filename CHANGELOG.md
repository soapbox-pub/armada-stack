# Changelog

A release's notes are its section here, so tag `vX.Y.Z` only once
`## X.Y.Z` exists: publishing fails without it.

## Unreleased

- A built-in Web Push service, `[push]`, on by default. It speaks
  nostr-push2's protocol (kind 25742), so the web app needs no changes:
  `window.ENV` points `NOSTR_PUSH2_PUBKEY` and `NOSTR_PUSH2_RELAYS` at it.
  Its key is made on first start, at `push/key` in the storage directory.
  It pushes events stored on this relay only: NIP-17 DMs to users whose DM
  relay this is, and Concord channels hosted here. Group chats and DMs on
  other relays don't notify. Unlike nostr-push2, it takes only filters for
  gift wraps, to one `#p` or by `authors`, as Armada sends them; filters
  only for kinds the relay doesn't store are dropped. `#p` has to be a hex
  pubkey, and a client's subscriptions may come to at most 60,000 bytes of
  JSON, so `get` can always answer. Set
  `NOSTR_PUSH2_PUBKEY` and
  `NOSTR_PUSH2_RELAYS` in `[web.env]` to keep using another push service.
- The relay takes kind 25742, which only filters that name its author or
  `#p` recipient can read.
- A relay query stops once its subscription is closed or replaced, or its
  connection goes, rather than running to the end for nobody. Each client
  address may have `relay.max_queries_per_ip` (4) queries running or
  waiting for a core at once, and a REQ's filters together examine at most
  200,000 events, so one client can't keep everyone else's REQs waiting.
- Each client address may send `relay.reqs_per_minute_per_ip` (1,200) REQs
  a minute across its connections. `relay.max_filters` is now 32 by
  default, down from 100: Armada sends at most 32 in one REQ.
  `relay.max_subscriptions` is now 64, up from 32, as Armada may open
  dozens at once at startup.
- A REQ's filters may list at most `relay.max_filter_values` (10,000) ids,
  authors, kinds and tag values between them, and each client address's
  open subscriptions at most `relay.max_filter_values_per_ip` (200,000),
  since they're held in memory while open. Armada's largest REQ lists about
  5,500.

## 0.2.0

- `armada upgrade` installs the latest signed release over the running
  binary and restarts the service, as rerunning install.sh does.
  `--check` only says whether there's one; `--version` picks a release.
  To get it from 0.1.0, rerun install.sh once.
- The relay no longer asks for NIP-42 AUTH, which tied each reader's key to
  the address they connect from. What may be read is up to the filter alone:
  gift wraps and NIP-46 messages need a filter naming their author or `#p`
  recipient. NIP-70 protected events are refused. `relay.max_authed_keys` is
  ignored, so configs that set it still load.
- install.sh, at https://armada.buzz/install.sh, installs the latest signed
  release and sets up a server with HTTPS; rerun it to upgrade.

## 0.1.0

First release: Armada's web app, a relay, a Blossom server, and a Concord AV
broker in one binary, with HTTPS from Let's Encrypt. Static builds for Linux
on x86_64 and aarch64.
