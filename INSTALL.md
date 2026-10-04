# Installing armada

`armada` is one binary that serves Armada's web app, a Nostr relay, a Blossom
server, and optionally a Concord AV broker, all from one domain. This guide
sets it up on a Linux server with its own HTTPS certificate from Let's
Encrypt. You won't need a reverse proxy.

## What you need

- A Linux server with systemd and a public IP address, on x86_64 or aarch64
  (ARM64). 2 CPUs and 4 GB of RAM is plenty to start.
- A domain or subdomain you can point at it, such as `armada.example.com`.
- Ports 80 and 443 open to the internet. Let's Encrypt checks port 80 when it
  issues the certificate.

## 1. Point DNS at the server

Create an `A` record for your domain with the server's IPv4 address. If the
server has IPv6, add an `AAAA` record for it too.

**If you use Cloudflare, turn the proxy off (grey cloud, "DNS only").**
armada handles TLS itself, and the relay and Blossom server must be reached
directly.

Check it before going on:

```sh
dig +short armada.example.com
```

## 2. Open the firewall

Allow inbound TCP 22 (SSH), 80, and 443. On Ubuntu with `ufw`:

```sh
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

If your host has a cloud firewall, such as DigitalOcean's, open the same
ports there.

## 3. Install

On the server, run [`install.sh`](install.sh) as root with your domain:

```sh
curl -fsSL <install.sh URL> | sudo sh -s -- armada.example.com
```

From a copy of this repository, that's `sudo sh install.sh armada.example.com`.
Add `--email you@example.com` to give Let's Encrypt an address to write to
about the certificate.

The script:

1. Finds the latest release on Nostr relays and checks that it's signed by
   Soapbox's key, `npub10qdp2fc9ta6vraczxrcs8prqnv69fru2k6s2dj48gqjcylulmtjsg9arpj`.
2. Downloads the binary for the server's architecture and checks it against
   the sha256 in that signed release.
3. Installs it at `/usr/local/bin/armada`, creates an `armada` user, and
   writes `/etc/armada/armada.toml`. An existing config is left alone.
4. Installs the [`deploy/armada.service`](deploy/armada.service) unit, starts
   it, and waits until the site answers over HTTPS.

It needs Python 3 to check the signature, and installs it if the server
doesn't have it. It finishes in about a minute:

```
armada: found armada-stack 0.1.0, released 2026-10-04, signed by Soapbox
armada: downloaded https://blossom.ditto.pub/d254…e1a5 and checked its sha256, d254…e1a5
armada: installed armada 0.1.0 at /usr/local/bin/armada
armada: created the armada user
armada: wrote /etc/armada/armada.toml; every other setting has a default
armada: started the armada service; getting a certificate for armada.example.com
armada: armada is running at https://armada.example.com/
```

The certificate renews in the background. armada also checks the relays for
new versions of the web app and deploys them on its own.

The config it writes is all armada needs; `armada.example.toml` lists and
explains every other setting. After changing it, run `systemctl restart armada`.

## 4. Check it

```sh
# Plain HTTP redirects to HTTPS
curl -sI http://armada.example.com/ | head -2

# The relay's information document
curl -s -H 'Accept: application/nostr+json' https://armada.example.com/

# What the web app is told to use
curl -s https://armada.example.com/_armada/env.js
```

Then open `https://armada.example.com` in a browser. The app uses this
server's relay and Blossom server alongside Armada's public ones.

## Upgrading

Run the installer again. Without a domain, it replaces the binary with the
latest release and restarts the service:

```sh
curl -fsSL <install.sh URL> | sudo sh
```

`--version 0.1.0` installs a particular release instead, to go back to one.

## Backups

Everything armada keeps is in `storage_dir` (`/var/lib/armada`): the relay's
events, Blossom blobs, the downloaded web app, and the TLS certificate and
ACME account. Stop the service before copying it, so the relay's database is
copied in a consistent state:

```sh
systemctl stop armada
tar -C /var/lib -czf armada-backup.tar.gz armada
systemctl start armada
```

## Voice and video calls (optional)

Calls need a [LiveKit](https://livekit.io) server for armada to broker calls
on. They're off until one is configured. To run LiveKit on the same machine:

1. Install `livekit-server` and generate an API key and secret for it.
2. Run it with [`deploy/livekit.yaml`](deploy/livekit.yaml). The comments in
   that file explain each setting. Its signaling stays on loopback, and
   armada forwards `wss://<domain>/rtc` to it.
3. Open 7881/tcp and 7882/udp for media.
4. Add the node to `armada.toml` and restart armada:

   ```toml
   [[av.nodes]]
   url = "wss://armada.example.com"
   api_url = "http://127.0.0.1:7880"
   api_key = "APIxxxxxxxxxxxx"
   api_secret = "..."
   ```

## Behind a reverse proxy instead

If something else already owns ports 80 and 443 on the server, leave `[tls]`
off and let the proxy terminate TLS. armada listens on `127.0.0.1:8080` by
default. Because that's a loopback address, it trusts `X-Forwarded-For` and
`X-Forwarded-Proto` from the proxy:

```toml
storage_dir = "/var/lib/armada"
public_url = "https://armada.example.com"
```

The proxy must pass WebSocket upgrades through, for the relay and `/rtc`.
It must not buffer or limit request bodies below the Blossom upload size,
which is 100 MB by default.

## Installing by hand

Without systemd, or to see each step, install armada yourself.

**Get the binary.** Running `install.sh` with no domain installs the latest
release's binary and nothing else. Or download a release directly. Release
binaries are statically linked, so they run on any distribution. They're
listed by [ngit](https://ngit.dev/install), which has to run inside a git
repository:

```sh
REPO=nostr://npub10qdp2fc9ta6vraczxrcs8prqnv69fru2k6s2dj48gqjcylulmtjsg9arpj/git.shakespeare.diy/armada-stack
git init -q /tmp/armada-releases && cd /tmp/armada-releases
ngit release list --repo "$REPO"
ngit release view armada-stack@0.1.0 --repo "$REPO" --verify
```

`view` prints each file's URL and sha256, and `--verify` downloads and checks
them. For 0.1.0, on x86_64 (use the aarch64 URL on ARM64):

```sh
# x86_64
curl -fLo armada-0.1.0-linux-x86_64 https://blossom.ditto.pub/d2545811934f7c1eeffe28968ecba3056bae6b016aa5f50187cbc859202be1a5
# aarch64
curl -fLo armada-0.1.0-linux-aarch64 https://blossom.ditto.pub/5a2debc9dd2df2522749463b6585f5a088315a600b6ff83e78f9ac8342573d36

curl -fLo SHA256SUMS https://blossom.ditto.pub/6e7a0bf1f73f11b31e18c4d7ec4d00ba31de09797a57cb0fa00f9e4b5b1298ef
sha256sum --check --ignore-missing SHA256SUMS
install -m 755 armada-0.1.0-linux-x86_64 /usr/local/bin/armada
```

**Configure it.** Create a user for it and write `/etc/armada/armada.toml`:

```sh
useradd --system --home-dir /var/lib/armada --shell /usr/sbin/nologin armada
mkdir -p /etc/armada
```

```toml
storage_dir = "/var/lib/armada"
public_url = "https://armada.example.com"

[tls]
acme = true
# email = "you@example.com"
```

**Run it.** Under systemd, copy [`deploy/armada.service`](deploy/armada.service)
to `/etc/systemd/system/`, then:

```sh
systemctl daemon-reload
systemctl enable --now armada
journalctl -u armada -f
```

Elsewhere, run `/usr/local/bin/armada --config /etc/armada/armada.toml` as the
`armada` user, with permission to bind ports 80 and 443 (for example
`setcap cap_net_bind_service=+ep /usr/local/bin/armada`).

To upgrade, install the new binary under a new name and move it into place,
so the running one is never half-overwritten, then restart:

```sh
install -m 755 armada-X.Y.Z-linux-x86_64 /usr/local/bin/armada.new
mv /usr/local/bin/armada.new /usr/local/bin/armada
systemctl restart armada
```

## Building from source

You need Rust 1.88 or newer and a C compiler, because the build compiles
LMDB:

```sh
git clone nostr://npub10qdp2fc9ta6vraczxrcs8prqnv69fru2k6s2dj48gqjcylulmtjsg9arpj/git.shakespeare.diy/armada-stack
cd armada-stack
cargo build --release
```

Cloning a `nostr://` URL needs [ngit](https://ngit.dev/install). The binary is
`target/release/armada`. It links glibc dynamically, so build it on a machine
whose glibc is no newer than the server's. The simplest way is to build on the
server itself.

The release binaries are built differently: statically against musl, by
[cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild). See
`.ngit/act/workflows/release.yml`.

## Logs

`RUST_LOG` sets the log level (`info` by default). `LOG_FORMAT=json` writes
one JSON object per line. To set them under systemd, run
`systemctl edit armada` and add:

```ini
[Service]
Environment=RUST_LOG=debug
```
