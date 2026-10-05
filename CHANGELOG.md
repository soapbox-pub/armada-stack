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

### Security

- Without `public_url`, the relay took its own name from each request's
  `Host`, so anyone could replay here a NIP-62 request to vanish that its
  author had meant for another relay, deleting their events. Now it takes
  only `ALL_RELAYS` requests then. armada warns at startup when
  `public_url` is unset.
- A request to vanish was carried out in full each time it was sent, in
  the one write transaction, so resending one stalled every write. Now
  one no newer than a request already taken costs nothing, and a new one
  is carried out in bounded steps.
- One event that couldn't be stored failed every other event in its batch.
- A REQ's results are capped at 16 MiB. Clients that stop reading for a
  minute, or go silent for two, are dropped; so are subscriptions whose
  query falls 4,096 live events behind.
- `relay.event_bytes_per_hour_per_ip` (256 MiB) bounds how fast one client
  can fill the disk. Every message a connection sends costs one of 3,000 a
  minute. Matching tags costs queries as examining events does.
- An EVENT reusing a stored id with a bad signature was answered as a
  duplicate, confirming a gift wrap was stored. Signatures must now be
  lowercase hex.
- Every listener — HTTPS, the port-80 redirect, and plain HTTP — now has a
  30-second header timeout, which hyper skipped without a timer, and
  closes connections idle for two minutes. There are at most 32,768
  connections at once, and 256 from one address unless behind a proxy.
- Blossom uploads time out after 15 minutes, or 30 seconds without data.
  Every byte received counts against `blossom.upload_bytes_per_hour`, kept
  or not, and a declared length is held against it while the upload runs.
  At most 64 uploads and mirrors run at once, 4 per client. Uploads that
  would leave less than `blossom.min_free_space` (1 GiB) on the disk are
  refused. Tokens signed more than a day ago are refused, whatever their
  expiration, and deletes are limited to 120 a minute per client.
- The push service takes at most 1,200 new clients an hour, and creates
  from one endpoint site 120 an hour; all clients' subscriptions may list
  a million filter values; and pushes to one host are capped at 3,000 a
  minute, so it can't be aimed at someone else's server.
- An `X-Forwarded-For` entry that isn't an address is ignored for the
  socket peer, and a port on one is dropped. armada says at startup what
  trusting the header, the default behind a loopback listener, asks of
  the proxy.
- Blob downloads and pushes ignore proxies from the environment, which
  would resolve names past the check for private addresses.
- `/rtc` forwards only plain paths, and drops client-sent headers that
  would tell the node someone else is the client.
- `/_armada/env.js` is `Cache-Control: private` and varies by `Host`.
- Failed deploys no longer keep what superseded versions downloaded, and
  downloads can cross `web.max_site_size` by one file at most, not four.
- `armada upgrade` and install.sh no longer install an older release than
  the one installed unless given `--version`. `armada upgrade` refuses to
  write the new binary in a directory others can write to.
- install.sh makes `/etc/armada/armada.toml` readable only by root and the
  armada user, as it can hold an AV node's `api_secret`. Run it again to
  fix an existing install.
- The systemd unit is hardened further: a syscall filter, no W^X memory,
  private devices, and the kernel, `/proc`, and namespaces walled off.
  `armada upgrade` installs the unit of the binary doing the upgrading, so
  run it once more after upgrading to this release, or rerun install.sh.

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
