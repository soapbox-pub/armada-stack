# Installing armada

`armada` is one binary that serves Armada's web app, a Nostr relay, a Blossom
server, and optionally a Concord AV broker, all from one domain. This guide
sets it up on a Linux server with its own HTTPS certificate from Let's
Encrypt. You won't need a reverse proxy.

## What you need

- A Linux server with a public IP address. 2 CPUs and 4 GB of RAM is plenty
  to start. Ubuntu 24.04 is what this guide was tested on.
- A domain or subdomain you can point at it, such as `armada.example.com`.
- Ports 80 and 443 open to the internet. Let's Encrypt checks port 80 when it
  issues the certificate.

## 1. Download

Each release has prebuilt binaries for Linux on x86_64 and on aarch64
(ARM64). They're statically linked, so they run on any distribution. Their
download links are in the release on gitworkshop.dev, under
`nostr://npub10qdp2fc9ta6vraczxrcs8prqnv69fru2k6s2dj48gqjcylulmtjsg9arpj/git.shakespeare.diy/armada-stack`.
With [ngit](https://ngit.dev/install) installed, this lists the same links:

```sh
ngit release list --repo nostr://npub10qdp2fc9ta6vraczxrcs8prqnv69fru2k6s2dj48gqjcylulmtjsg9arpj/git.shakespeare.diy/armada-stack
ngit release view armada-stack@0.1.0 --repo nostr://npub10qdp2fc9ta6vraczxrcs8prqnv69fru2k6s2dj48gqjcylulmtjsg9arpj/git.shakespeare.diy/armada-stack
```

Releases are signed by Soapbox's key, `npub10qdp2…`. Check that before
trusting one.

On the server, download the binary for its architecture (`uname -m` says
which) and the release's `SHA256SUMS`, and check one against the other:

```sh
curl -fLo armada-0.1.0-linux-x86_64 <binary URL from the release>
curl -fLo SHA256SUMS <SHA256SUMS URL from the release>
sha256sum --check --ignore-missing SHA256SUMS
```

To build it yourself instead, see [Building from source](#building-from-source).

## 2. Point DNS at the server

Create an `A` record for your domain with the server's IPv4 address. If the
server has IPv6, add an `AAAA` record for it too.

**If you use Cloudflare, turn the proxy off (grey cloud, "DNS only").**
armada handles TLS itself, and the relay and Blossom server must be reached
directly.

Check it before going on:

```sh
dig +short armada.example.com
```

## 3. Open the firewall

Allow inbound TCP 22 (SSH), 80, and 443. On Ubuntu with `ufw`:

```sh
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

If your host has a cloud firewall, such as DigitalOcean's, open the same
ports there.

## 4. Install

Install the binary and create a user for it to run as:

```sh
install -m 755 armada-0.1.0-linux-x86_64 /usr/local/bin/armada
useradd --system --home-dir /var/lib/armada --shell /usr/sbin/nologin armada
mkdir -p /etc/armada
```

Write `/etc/armada/armada.toml`:

```toml
storage_dir = "/var/lib/armada"
public_url = "https://armada.example.com"

[tls]
acme = true
# Optional: Let's Encrypt emails this address if something goes wrong
# with the certificate.
# email = "you@example.com"
```

That's all the configuration you need. Every other setting has a default;
`armada.example.toml` lists and explains them all.

## 5. Run it as a service

Copy [`deploy/armada.service`](deploy/armada.service) to
`/etc/systemd/system/armada.service`, then:

```sh
systemctl daemon-reload
systemctl enable --now armada
journalctl -u armada -f
```

On first start you should see, within a minute or so:

```
INFO armada::tls: no TLS certificate yet; asking the CA for one domain="armada.example.com" ...
INFO armada::tls::acme: TLS certificate issued domain="armada.example.com" ...
INFO armada::web::sync: deploying ... files=251 blobs=250 missing=250
INFO armada::web::sync: version live ...
```

The certificate renews in the background. armada also checks the relays for
new versions of the web app and deploys them on its own.

## 6. Check it

```sh
# Plain HTTP redirects to HTTPS
curl -sI http://armada.example.com/ | head -2

# The web app
curl -s -o /dev/null -w '%{http_code}\n' https://armada.example.com/

# The relay's information document
curl -s -H 'Accept: application/nostr+json' https://armada.example.com/

# What the web app is told to use
curl -s https://armada.example.com/_armada/env.js
```

Then open `https://armada.example.com` in a browser. The app uses this
server's relay and Blossom server alongside Armada's public ones.

## Upgrading

Download and check the new release's binary as in step 1, then put it in
place and restart:

```sh
install -m 755 armada-X.Y.Z-linux-x86_64 /usr/local/bin/armada.new
mv /usr/local/bin/armada.new /usr/local/bin/armada
systemctl restart armada
```

Installing under a new name and then moving it into place replaces the file
in one step, so the running binary is never half-overwritten.

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
