# Changelog

A release's notes are its section here, so tag `vX.Y.Z` only once
`## X.Y.Z` exists: publishing fails without it.

## Unreleased

- `armada upgrade` installs the latest signed release over the running
  binary and restarts the service, as rerunning install.sh does.
  `--check` only says whether there's one; `--version` picks a release.

## 0.1.0

First release: Armada's web app, a relay, a Blossom server, and a Concord AV
broker in one binary, with HTTPS from Let's Encrypt. Static builds for Linux
on x86_64 and aarch64.
