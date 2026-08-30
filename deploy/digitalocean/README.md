# Armada on a DigitalOcean droplet

Two ways to stand up the whole stack — client, voice, relay, push, media — on
one DigitalOcean droplet. Both bring it up in **pull mode**: the relay, broker
and push images are pulled pre-built from
[ncontainer.io](https://ncontainer.io), and only the client is built on the box
(its endpoint URLs are baked into the bundle at build time from your own
hostnames, so it can't be a pre-published image — see
`../../docker-compose.pull.yml`).

The result is that a self-hoster needs **Docker and one source tree
(`../armada`)** instead of four source trees plus a Bun toolchain.

## What you need first

- A **domain you control**, so you can create four DNS records under it. This
  droplet is domain-entry: it does not invent a hostname for you.
- A DigitalOcean account.
- ~4 GB RAM (OpenSearch is the heavy part). The $24/mo **4 GB / 2 vCPU** basic
  droplet is the floor; 8 GB is comfortable.

## Path A — cloud-init (paste one file)

The lowest-effort path that needs no image building on your side.

1. **Edit two lines.** Open [`cloud-init.yml`](./cloud-init.yml) and set
   `DOMAIN` and `EMAIL` in the `deploy.env` block near the top. Set `STACK_REPO`
   to this repo's published clone URL (see [Publishing the stack](#publishing-the-stack)
   — until it's published there is nothing for the droplet to clone).

2. **Create the droplet.** In the DigitalOcean panel: **Create → Droplets →**
   Ubuntu 24.04, a 4 GB plan, then under **Advanced options → Add
   Initialization scripts (free)** paste the whole edited file. Create.

3. **Point four DNS records at the droplet's IP** — four `A` records:

   ```
   armada.<your-domain>   → <droplet IP>
   av.<your-domain>       → <droplet IP>
   relay.<your-domain>    → <droplet IP>
   blossom.<your-domain>  → <droplet IP>
   ```

   Caddy cannot issue TLS certificates until these resolve to the droplet, so
   the stack boots but serves nothing until you do this. This is the one step
   no button can do for you — the records live in a domain DigitalOcean does not
   host.

4. **Wait.** First boot installs Docker, sets sysctls, opens the firewall,
   fetches the stack + client source, and builds. Watch it:

   ```sh
   ssh root@<droplet IP>
   tail -f /var/log/armada-firstboot.log
   docker compose -f /opt/armada/stack/docker-compose.yml \
                  -f /opt/armada/stack/docker-compose.pull.yml ps
   ```

   Then open `https://armada.<your-domain>`.

If you created the droplet before editing `deploy.env`, or DNS wasn't ready:
fix `/opt/armada/deploy.env` and re-run `bash /opt/armada/firstboot.sh` — it's
idempotent (guarded by `/opt/armada/.provisioned`), so it won't rotate keys or
re-clone.

## Path B — a Marketplace-style 1-Click image (Packer)

The truest "one click": bake Docker, the sysctls, the stack and the client
source into a **snapshot**, so first boot clones nothing and only needs your
domain. This is also what a DigitalOcean Marketplace listing is under the hood —
a Packer-built snapshot plus DO's review.

The build baked image still can't skip DNS or the client build (its URLs aren't
known until you pick a domain), but everything else is done before the droplet
exists.

Sketch (`packer/armada.pkr.hcl`, not yet written — see
[Not built yet](#not-built-yet)):

- Source: DigitalOcean builder on Ubuntu 24.04.
- Provisioner: run the same steps `firstboot.sh` does **except** `bootstrap.sh`
  and `up` — install Docker, write the sysctls, `git clone` the stack and client
  into `/opt/armada`, and pre-pull the three ncontainer images so the first real
  boot is fast.
- A `cloud-init` per-instance script that reads `DOMAIN`/`EMAIL` (from user-data
  or a DO Marketplace form) and runs only `bootstrap.sh --pull` + `up`.

DigitalOcean's Marketplace requires the image pass their
[1-Click app requirements](https://docs.digitalocean.com/products/marketplace/)
(a `018-` cleanup script, no baked secrets, first-boot MOTD). The stack already
generates every secret on first boot via `bootstrap.sh`, so nothing secret is
in the image — which is the hard part of passing review.

## Why not a PaaS deploy button?

Render, Railway, Fly's managed tier, DO App Platform: none of them do arbitrary
**UDP** or host **sysctls**, and both are load-bearing here —

- `7882/udp` is the voice media path (LiveKit). Without it voice connects and
  then carries no audio.
- `vm.max_map_count=262144` (OpenSearch won't start below it) and
  `net.core.rmem_max=5000000` (LiveKit media buffer) are host-kernel settings a
  container inherits and cannot set.

So the target is a raw droplet, not a PaaS. `../../scripts/preflight.sh` checks
all of this before the first `up`.

## Publishing the stack

`cloud-init.yml`'s `STACK_REPO` has no default because this repo isn't published
anywhere yet, so a droplet has nothing to clone. Publish it once — e.g. over
nostr with ngit:

```sh
cd /home/chad/projects/armada-stack
ngit init --name "armada-stack" \
  --description "Turnkey self-hosted Armada deployment"
git push -u origin master
```

Then set `STACK_REPO` to the `nostr://…` URL `ngit repo --json` reports (the
cloud-init installs ngit automatically when `STACK_REPO` is a `nostr://` URL).
Any ordinary `https://` git host works too.

## Firewall

`cloud-init.yml` configures the on-host `ufw`. If you also add a DigitalOcean
**Cloud Firewall** in the panel, it must allow the same inbound set or it will
override the host rules:

| Port | Proto | Why |
|---|---|---|
| 22 | tcp | SSH |
| 80 | tcp | HTTP → Caddy (ACME + redirect) |
| 443 | tcp | HTTPS |
| 443 | udp | HTTP/3 |
| 7881 | tcp | LiveKit ICE/TCP fallback |
| 7882 | udp | LiveKit media mux — **voice is silent without it** |

## Not built yet

- `packer/armada.pkr.hcl` and the per-instance script for Path B.
- A true DigitalOcean Marketplace submission (needs the `018-`/`90-` cleanup
  scripts and a listing).
- The no-DNS `sslip.io` fallback (declined for the first droplet — it's the
  runtime-config path the client doesn't have yet).
