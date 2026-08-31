# Armada on a DigitalOcean droplet

Two ways to stand up the whole stack — client, voice, relay, push, media — on
one DigitalOcean droplet. Both bring it up in **pull mode**: the relay, broker
and push images are pulled pre-built from
[ncontainer.io](https://ncontainer.io), and the client is built from a
**git-URL context** (BuildKit clones the client repo at build time) with its
endpoint URLs baked in from your own hostnames — it can't be a pre-published
image because those URLs aren't known until you pick a domain (see
`../../docker-compose.pull.yml`).

The result is that a droplet needs **Docker and no source trees at all**:
two images and a git URL, reproducible from URLs alone. Nothing lands on a
local `../` sibling path.

## What you need first

- A **domain you control**, so you can create four DNS records under it. This
  droplet is domain-entry: it does not invent a hostname for you.
- A DigitalOcean account.
- ~4 GB RAM (OpenSearch is the heavy part). The $24/mo **4 GB / 2 vCPU** basic
  droplet is the floor; 8 GB is comfortable.

## Path A — cloud-init (paste one file)

The lowest-effort path that needs no image building on your side.

1. **Edit the config.** Open [`cloud-init.yml`](./cloud-init.yml) and set
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

4. **Wait.** First boot opens the firewall, sets sysctls, clones the stack, and
   runs its `firstboot.sh` — which installs Docker, pulls the three images,
   builds the client from its git URL, and brings the stack up. Watch it:

   ```sh
   ssh root@<droplet IP>
   tail -f /var/log/armada-firstboot.log
   docker compose -f /opt/armada/stack/docker-compose.yml \
                  -f /opt/armada/stack/docker-compose.pull.yml ps
   ```

   Then open `https://armada.<your-domain>`.

If you created the droplet before editing `deploy.env`, or DNS wasn't ready:
fix `/etc/armada/deploy.env` and re-run
`bash /opt/armada/stack/deploy/digitalocean/firstboot.sh`. It's idempotent
(guarded by `/var/lib/armada/.provisioned`), and an unconfigured box exits 0
without writing the marker — so it simply retries on the next run rather than
rotating keys or re-cloning.

## Path B — a Marketplace-style 1-Click image (Packer)

The truest "one click": bake Docker, the sysctls, the stack and the three
pulled images into a **snapshot**, so first boot only needs your domain. This is
also what a DigitalOcean Marketplace listing is under the hood — a Packer-built
snapshot plus DO's review.

The baked image still can't skip DNS or the client build (its URLs aren't known
until you pick a domain), but everything else is done before the droplet exists.

### Build the image

Needs [Packer](https://developer.hashicorp.com/packer/install) and a
DigitalOcean API token with write scope.

```sh
cd deploy/digitalocean/packer
export DIGITALOCEAN_API_TOKEN=dop_v1_...
packer init .
packer build .
```

The build ([`armada.pkr.hcl`](./packer/armada.pkr.hcl)) spins up a throwaway
Ubuntu 24.04 droplet, uploads this checkout, runs
[`provision.sh`](./packer/provision.sh) (Docker, the stack at
`/opt/armada/stack`, the sysctls, the pre-pulled images, the
[`armada-firstboot.service`](./armada-firstboot.service) unit, an MOTD), then
runs DigitalOcean's own `90-cleanup.sh` / `99-img_check.sh` and snapshots. The
snapshot name is printed at the end (`armada-stack-<timestamp>`).

`provision.sh` strips `.env` and `.git` from the baked copy and
deletes the staging upload, so **no secret rides into the snapshot** — which is
the hard requirement for passing Marketplace review. Every stack secret is
generated on the operator's first boot by `bootstrap.sh`.

### Launch and test a droplet from it

With [`doctl`](https://docs.digitalocean.com/reference/doctl/how-to/install/):

```sh
# Find the snapshot the build produced.
doctl compute snapshot list --format ID,Name | grep armada-stack

# user-data supplies the operator config the image left as placeholders.
cat > /tmp/user-data.yml <<'EOF'
#cloud-config
write_files:
  - path: /etc/armada/deploy.env
    permissions: '0600'
    content: |
      DOMAIN=example.com
      EMAIL=you@example.com
EOF

doctl compute droplet create armada-test \
  --image <snapshot-id> \
  --size s-2vcpu-4gb \
  --region nyc3 \
  --ssh-keys <your-key-fingerprint> \
  --user-data-file /tmp/user-data.yml \
  --wait

# Point the four DNS records at the new droplet's IP, then watch it come up.
doctl compute droplet get armada-test --format PublicIPv4
ssh root@<ip> tail -f /var/log/armada-firstboot.log
```

The `armada-firstboot` unit runs on every boot until provisioned, so if you set
`deploy.env` after first boot, `systemctl start armada-firstboot` (or a reboot)
brings it up. Tear the test down with `doctl compute droplet delete armada-test`.

### Submit to the Marketplace

The image is built to DO's
[1-Click app requirements](https://docs.digitalocean.com/products/marketplace/)
(the `90-cleanup.sh` / `99-img_check.sh` scripts run in the build, no baked
secret, a first-boot MOTD). What remains is DO's own vendor onboarding and
listing — a manual submission, not something the build can do.

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

Path B (Packer) does not need the stack published — it uploads the checkout
directly — so you can build and test a Marketplace image before publishing.

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

- A true DigitalOcean Marketplace listing (the image passes `99-img_check.sh`;
  the submission itself is manual vendor onboarding).
- The no-DNS `sslip.io` fallback (declined for the first droplet — it's the
  runtime-config path the client doesn't have yet).
