# Changelog

A release's notes are its section here, so tag `vX.Y.Z` only once
`## X.Y.Z` exists: publishing fails without it.

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
