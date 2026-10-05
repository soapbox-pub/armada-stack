# Changelog

A release's notes are its section here, so tag `vX.Y.Z` only once
`## X.Y.Z` exists: publishing fails without it.

## Unreleased

- Calls, built in. armada carries LiveKit 1.13.7 and runs it itself, as the
  node its AV broker places calls on, so a new server has voice and video
  with nothing to install. Its signaling goes through armada at `/rtc`;
  **open 7881/tcp and 7882/udp** for the media. Its key and secret are made
  on first start, in `livekit/` in the storage directory. `[av] livekit =
  false` turns it off, and a node in `[[av.nodes]]` on armada's own origin
  takes its place. It needs `public_url`. The binary is about 20 MB larger.
- `window.ENV` gives `CONCORD_AV_SERVERS` as this armada alone, rather than
  this armada then armada.buzz.
- install.sh raises the kernel's UDP buffer limits for LiveKit, in
  `/etc/sysctl.d/60-armada.conf`. The service unit no longer hides the rest
  of `/proc` (`ProcSubset=pid`), which LiveKit reads the machine's load from;
  install.sh installs the new unit, or copy `deploy/armada.service` in.

- `window.ENV` names the web app's relays and Blossom servers the way
  Armada now reads them: `RELAYS` and `BLOSSOM_SERVERS`, armada's own first,
  in place of `APP_RELAYS`, `COMMUNITY_RELAYS`, `APP_BLOSSOM_SERVERS` and
  `PREFERRED_BLOSSOM_SERVER`. `RELAYS` is every relay the app uses by
  default, the backups of each user's community and invite lists included,
  so setting it in `[web.env]` to this relay alone keeps the app off every
  other relay. Armada's versions from before the change don't read it.
  **A `[web.env]` that sets the old names does nothing now; rename them.**

## 0.3.1

- install.sh sets up a new server again. It enabled the systemd unit before
  copying it in, so on a server without one it stopped, silently, after
  writing the config.
- Until the web app has downloaded, a browser gets an Armada page, with
  the app's animated crest and ASCII sea, that says how far the download
  has got and opens the app once it's live, rather than a line of text.
  Other requests still get the plain 503. It asks
  `/_armada/status.json`, which says the stage (`searching`, `not_found`,
  `downloading` with counts, `failed`, or `live`) and never why a deploy
  failed; that's in the log.
- armada says when Tor has published the onion, and warns when Tor reports
  a problem with it. Publishing can take several minutes after a start, and
  until then the onion can't be reached; it used to say it was serving the
  onion as soon as it launched it.

## 0.3.0

- Tor, built in, with no tor daemon to install. armada is served as an
  onion service by default, at an address made on first start; `armada
  onion` prints it. Its key is `tor/hs_ed25519_secret_key` in the storage
  directory, in C Tor's format, so back it up to keep the address. Clients
  that come over the onion are pointed at the onion's relay and Blossom
  server in `window.ENV`, and aren't offered AV. Pages served over HTTPS
  send `Onion-Location`. The relay takes requests to vanish naming either
  of its names. Each Tor circuit counts as one client for the per-address
  limits, and proxy headers on onion requests are dropped. `[tor]
  onion_service = false` stops serving the onion; `[tor] enabled = false`
  turns Tor off altogether (both on by default).
- Relays at `.onion` addresses are reached over Tor, both configured ones
  and those in an nsite author's relay list, so the site can be followed on
  relays that are only onions. An author's may be `ws://`.
- Building needs Rust 1.92.
- The relay's NIP-11 document has an `icon` and a `banner`: Armada's logo
  and social card, built into the binary and served at
  `/_armada/icon.png` and `/_armada/banner.png`, whatever site is live.
- Blossom uploads and mirrors may ask to expire, with `X-Expiration: <unix
  time>` (blossom#115), as Armada does for attachments to disappearing
  messages. It's rounded up to the end of its day. A blob goes once every
  uploader's claim on it has expired, never while anyone keeps it for good,
  so an avatar can't vanish because the same bytes were attached to a
  disappearing message. Its expiration is in the descriptor and in a
  `Sunset` header, it's not served past it, and an hourly sweep deletes it.
  Blobs uploaded before, and uploads without the header, are kept as ever.
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
