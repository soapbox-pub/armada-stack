# Installing armada

`armada` is one binary that serves Armada's web app, a Nostr relay, a Blossom
server, and voice and video calls, all from one domain. This guide
sets it up on a Linux server with its own HTTPS certificate from Let's
Encrypt. You won't need a reverse proxy.

## What you need

- A Linux server with systemd and a public IP address, on x86_64 or aarch64
  (ARM64). 2 CPUs and 4 GB of RAM is plenty to start.
- A domain or subdomain you can point at it, such as `armada.example.com`.
- Ports 80 and 443 open to the internet. Let's Encrypt checks port 80 when it
  issues the certificate. Calls also need 7881/tcp and 7882/udp.

## 1. Point DNS at the server

Create an `A` record for your domain with the server's IPv4 address. If the
server has IPv6, add an `AAAA` record for it too.

If you use Cloudflare, its proxy can be on (orange cloud) or off (grey
cloud, "DNS only"). Off is simplest. On, armada tells visitors apart by the
address Cloudflare passes on, and still gets its own certificate. Then:

- Set SSL/TLS to **Full (strict)** in Cloudflare's dashboard. Flexible works
  too, but leaves the hop from Cloudflare to the server unencrypted.
- Calls' audio and video go to the server directly, not through
  Cloudflare, so the ports in step 2 still have to be open.
- Cloudflare's Free and Pro plans refuse uploads over 100 MB, a little less
  than armada's own limit. If that matters, set
  `[blossom] max_blob_size = 100000000` to match, so the app is told the
  real limit.

Check it before going on. With Cloudflare's proxy on, it shows Cloudflare's
addresses rather than the server's.

```sh
dig +short armada.example.com
```

## 2. Open the firewall

Allow inbound TCP 22 (SSH), 80, 443 and 7881, and UDP 7882. The last two
carry calls' audio and video. On Ubuntu or Debian with `ufw`:

```sh
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 7881/tcp
ufw allow 7882/udp
ufw enable
```

On Fedora, RHEL, Rocky, AlmaLinux or CentOS Stream with `firewalld`, which
allows SSH already:

```sh
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --permanent --add-port=7881/tcp
firewall-cmd --permanent --add-port=7882/udp
firewall-cmd --reload
```

Some cloud images, such as DigitalOcean's, come with neither turned on, and
nothing on the server to open. If your host has a cloud firewall, such as
DigitalOcean's, open the same ports there.

## 3. Install

On the server, run [`install.sh`](install.sh) as root with your domain:

```sh
curl -fsSL https://armada.buzz/install.sh | sudo sh -s -- armada.example.com
```

From a copy of this repository, that's `sudo sh install.sh armada.example.com`.
Add `--email you@example.com` to give Let's Encrypt an address to write to
about the certificate. Leave the domain off and it asks for one; leave the
answer blank and it installs only the package.

The script:

1. On Debian, Ubuntu, Fedora, RHEL and their relatives, adds the
   `armada-stack` package repository at
   [pkg.soapbox.pub](https://pkg.soapbox.pub/deb/soapbox.pub/armada-stack)
   and installs the package from it ([From a package](#from-a-package) says
   what it installs). pkg.soapbox.pub serves the releases Soapbox signs on
   Nostr, with indexes signed by its own key.
2. Anywhere else, downloads the latest release's binary from pkg.soapbox.pub,
   checks it against the release's sha256, and installs it at
   `/usr/local/bin/armada` with an `armada` user, the
   [`deploy/armada.service`](deploy/armada.service) unit, and the kernel UDP
   buffer limits calls need, in `/etc/sysctl.d/60-armada.conf`.
3. Sets `public_url` in `/etc/armada/armada.toml` to your domain. A config
   that already has one is left alone.
4. Enables and starts the service, and waits until the site answers over
   HTTPS.

It finishes in about a minute:

```
armada: added the armada-stack repository, /etc/apt/sources.list.d/armada-stack.sources
armada: installing armada-stack with apt
armada: installed armada-stack 0.5.1
armada: set public_url in /etc/armada/armada.toml to https://armada.example.com
armada: armada is running; waiting for https://armada.example.com/
armada: armada is running at https://armada.example.com/
armada: and over Tor at http://5h34fohc7jrfzdyzj2jadl3csmmqox5fsqknuzgi5bfbnlokgxakd6id.onion/
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
server's relay and Blossom server alongside Armada's public ones. On a new
server the app takes half a minute or so to download; until then the page
says how far it's got, and opens the app by itself once it's ready.

## Tor

armada runs Tor itself, with no tor daemon to install, and serves everything
as an onion service too: the web app, relay and Blossom server, over plain
HTTP on the onion's port 80, since Tor encrypts the connection itself. The
address is made the first time armada starts. Print it with:

```sh
sudo armada onion
```

A browser that comes over the onion is pointed at the onion's relay and
Blossom server rather than the domain's, so nothing it does leaves Tor.
Tor Browser visiting the domain is offered the onion (the `Onion-Location`
header). AV calls aren't offered over the onion: WebRTC can't go through Tor.

After armada starts, Tor takes anywhere from seconds to several minutes to
publish the onion, and it can't be reached until then; armada logs "Tor has
published the onion service" once it's up. Check it from any machine with Tor
running:

```sh
curl --socks5-hostname 127.0.0.1:9050 -H 'Accept: application/nostr+json' http://$(sudo armada onion)/
```

The address is its key, `tor/hs_ed25519_secret_key` in `storage_dir`. Back it
up to keep the address; lose it and the next start makes a new one. It's in
C Tor's format, beside the `hostname` and `hs_ed25519_public_key` C Tor keeps,
so an address can move to or from a C Tor `HiddenServiceDir` by copying those
three files.

Tor also lets armada reach relays that are onions, such as one an nsite's
author publishes to. To turn the onion service off but keep that, or turn
Tor off altogether, set these in the config and restart:

```toml
[tor]
onion_service = false  # no onion service
enabled = false        # no Tor at all
```

Tor needs nothing from the firewall: it only makes outbound connections.

## Upgrading

Installed from the package repository, armada upgrades with the rest of the
system:

```sh
sudo apt update && sudo apt upgrade    # or
sudo dnf upgrade
```

The package restarts armada if it was running, and keeps your config.

Anywhere else, run:

```sh
sudo armada upgrade
```

It finds the latest release on Nostr, trusting only Soapbox's signature, and
checks the binary against the sha256 in that release before moving it into
place. Then it refreshes the systemd unit and restarts the service, starting
it if it was stopped. If everything is already current and running, it
changes nothing. Your config is never rewritten.

`armada upgrade --check` only says whether there's a newer release, and
`--version 0.1.0` installs a particular release instead, to go back to one.

Either way, running the installer again also upgrades, with or without the
domain:

```sh
curl -fsSL https://armada.buzz/install.sh | sudo sh
```

It also waits for HTTPS to answer. A different domain from the config's is
refused: to move domains, edit `public_url` and restart.

Running it on a Debian or Fedora server set up by an earlier installer moves
it to the package: it installs `armada-stack`, removes
`/usr/local/bin/armada` and the `/etc/systemd/system/armada.service` that ran
it, and restarts armada. The config and `/var/lib/armada` are kept.

## Backups

Everything armada keeps is in `storage_dir` (`/var/lib/armada`): the relay's
events, Blossom blobs, the downloaded web app, the TLS certificate and ACME
account, and the onion's key. Stop the service before copying it, so the relay's database is
copied in a consistent state:

```sh
systemctl stop armada
tar -C /var/lib -czf armada-backup.tar.gz armada
systemctl start armada
```

## Voice and video calls

Calls run on [LiveKit](https://livekit.io), which is built into armada: it
runs it beside itself and brokers calls on it, with nothing to install. The
app is pointed at this server for calls, and nowhere else. LiveKit's
signaling goes through armada at `wss://<domain>/rtc`; only the media ports,
7881/tcp and 7882/udp, have to be open (step 2). Its key and secret are made
on first start, in `livekit/` in the storage directory.

Clients send media to the server's own public address, which armada reads
from its network interfaces. On a cloud server behind a NAT, such as AWS,
GCP or Azure, the interfaces only have a private address, so LiveKit finds
the public one over STUN instead, and can't start without it. There, give
it the public (or elastic) IP:

```toml
[av]
node_ip = "203.0.113.7"   # or "v4,v6"
```

Calls aren't offered over the onion, nor without `public_url`.

To run LiveKit yourself instead, on this machine or others, turn the
built-in one off and list your nodes:

```toml
[av]
livekit = false

[[av.nodes]]
url = "wss://armada.example.com"
api_url = "http://127.0.0.1:7880"
api_key = "APIxxxxxxxxxxxx"
api_secret = "..."
```

[`deploy/livekit.yaml`](deploy/livekit.yaml) is the config the built-in one
runs with, and explains each setting. A node on armada's own origin, as
above, takes the built-in one's place even without `livekit = false`.

## Behind a reverse proxy instead

If something else already owns ports 80 and 443 on the server, leave `[tls]`
off and let the proxy terminate TLS. armada listens on `127.0.0.1:8080` by
default. Because that's a loopback address, it tells clients apart by the
`X-Forwarded-For` entry the proxy appends:

```toml
storage_dir = "/var/lib/armada"
public_url = "https://armada.example.com"
```

The proxy must pass WebSocket upgrades through, for the relay and `/rtc`.
It must not buffer or limit request bodies below the Blossom upload size,
which is 100 MB by default.

## From a package

Each release also has the binaries as `.deb` and `.rpm` packages, for
Debian, Ubuntu, Fedora, RHEL and their relatives, served as package
repositories at pkg.soapbox.pub. `install.sh` adds the repository and
installs the package; to do it yourself, follow the steps for
[apt](https://pkg.soapbox.pub/deb/soapbox.pub/armada-stack) or
[dnf](https://pkg.soapbox.pub/rpm/soapbox.pub/armada-stack).

The package is named `armada-stack`. It puts the binary at `/usr/bin/armada`
rather than `/usr/local/bin`, and installs the `armada` user, the unit, the
UDP buffer limits, and an `/etc/armada/armada.toml` with `[tls] acme = true`
and `public_url` unset. `install.sh` sets `public_url` and starts it; without
it, set `public_url` yourself, then start it:

```sh
sudo $EDITOR /etc/armada/armada.toml
sudo systemctl enable --now armada
```

The service is left stopped and disabled until then, since it refuses to
start with `acme` on and no `public_url`. An upgrade keeps your config and
restarts armada if it was running. Removing the package stops and disables it
but keeps `/var/lib/armada` and the `armada` user; purging it also removes
the config. To change the unit, use `sudo systemctl edit armada` rather than
editing it, so the next upgrade doesn't undo it.

Moving by hand from a binary install, remove
`/etc/systemd/system/armada.service` and `/usr/local/bin/armada` after
installing the package: that unit overrides the package's and runs the old
binary. If `/etc/armada/armada.toml` is already
there, apt asks whether to replace it: keep yours, the default. dnf keeps it
without asking and puts the package's beside it as `armada.toml.rpmnew`.

## Installing by hand

Without systemd, or to see each step, install armada yourself.

**Get the binary.** Download it from the latest release:

```sh
curl -fLO https://pkg.soapbox.pub/releases/soapbox.pub/armada-stack/latest/download/armada-X.Y.Z-linux-x86_64
```

`https://pkg.soapbox.pub/releases/soapbox.pub/armada-stack/latest` lists its
files with their sha256s. Or find a release on Nostr yourself. Release
binaries are statically linked, so they run on any distribution. They're
listed by [ngit](https://ngit.dev/install), which has to run inside a git
repository:

```sh
REPO=nostr://npub10qdp2fc9ta6vraczxrcs8prqnv69fru2k6s2dj48gqjcylulmtjsg9arpj/git.shakespeare.diy/armada-stack
git init -q /tmp/armada-releases && cd /tmp/armada-releases
ngit release list --repo "$REPO"
ngit release view armada-stack@0.4.0 --repo "$REPO" --verify
```

`view` prints each file's URL and sha256, and `--verify` downloads and checks
them. Download the binary for your architecture by its URL and check it
against that sha256. For 0.4.0:

```sh
# x86_64
curl -fLo armada-0.4.0-linux-x86_64 https://blossom.ditto.pub/3dd21c68b9c3bd332fb4365977d7d6f13f5fc9e547d9a862efe84b3096f81a39
# aarch64
curl -fLo armada-0.4.0-linux-aarch64 https://blossom.ditto.pub/c5d33e36cad3d7d81909f380ce72fbf87141f190a1e17027de11a8d162d928ee

echo "3dd21c68b9c3bd332fb4365977d7d6f13f5fc9e547d9a862efe84b3096f81a39  armada-0.4.0-linux-x86_64" | sha256sum --check
install -m 755 armada-0.4.0-linux-x86_64 /usr/local/bin/armada
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

To upgrade, run `sudo armada upgrade`, which replaces whichever binary you
run it as and restarts the service if it's set up as above. By hand, install
the new binary under a new name and move it into place, so the running one is
never half-overwritten, then restart:

```sh
install -m 755 armada-X.Y.Z-linux-x86_64 /usr/local/bin/armada.new
mv /usr/local/bin/armada.new /usr/local/bin/armada
systemctl restart armada
```

## Building from source

You need Rust 1.92 or newer and a C compiler, because the build compiles
LMDB and SQLite:

```sh
git clone nostr://npub10qdp2fc9ta6vraczxrcs8prqnv69fru2k6s2dj48gqjcylulmtjsg9arpj/git.shakespeare.diy/armada-stack
cd armada-stack
cargo build --release
```

Cloning a `nostr://` URL needs [ngit](https://ngit.dev/install). The binary is
`target/release/armada`. It links glibc dynamically, so build it on a machine
whose glibc is no newer than the server's. The simplest way is to build on the
server itself.

That build has no LiveKit in it, so it offers calls only on nodes in
`[[av.nodes]]`. To build LiveKit in, name a `livekit-server` binary for the
target, from [LiveKit's releases](https://github.com/livekit/livekit/releases),
in `ARMADA_LIVEKIT`, and its version in `ARMADA_LIVEKIT_VERSION`:

```sh
ARMADA_LIVEKIT=/path/to/livekit-server ARMADA_LIVEKIT_VERSION=1.13.7 cargo build --release
```

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
