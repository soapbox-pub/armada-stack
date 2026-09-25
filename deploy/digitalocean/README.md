# Armada on DigitalOcean

Two ways onto a droplet. Both end in the same state, because both run the same
[`../cloud-init/firstboot.sh`](../cloud-init/firstboot.sh) after the same
[`../cloud-init/install-host.sh`](../cloud-init/install-host.sh).

## What you need first

- A **domain you control**, so you can create four DNS records under it.
- ~4 GB RAM (OpenSearch is the heavy part). The **4 GB / 2 vCPU** basic droplet
  is the floor; 8 GB is comfortable.

## Path A — cloud-init (paste one file)

Nothing DigitalOcean-specific: this is the generic
[`../cloud-init/cloud-init.yml`](../cloud-init/cloud-init.yml).

1. **Create → Droplets →** Ubuntu 24.04, a 4 GB plan, then under **Advanced
   options → Add Initialization scripts** paste the file with `DOMAIN` and
   `EMAIL` edited. (Leave them as placeholders and run `armada-setup` over SSH
   instead.)
2. **Point four `A` records at the droplet's IP:** `armada.`, `av.`, `relay.`,
   `blossom.` under your domain. These live in a domain DigitalOcean does not
   host, so no button can do it for you.
3. **Wait.** `ssh root@<ip> tail -f /var/log/armada-firstboot.log`. The client
   build takes a few minutes; firstboot ends by checking DNS. Then open
   `https://armada.<your-domain>`.

## Path B — a Marketplace 1-Click image (Packer)

Bakes Docker, the sysctls, the firewall, the stack and every pinned image into a
snapshot. A droplet made from it asks for its domain on the **first root SSH
login** (`armada-setup`), or takes it from user-data exactly like Path A — so
the only per-droplet work left is the secrets, the client build (its URLs are
the operator's hostnames, so it cannot be baked) and DNS.

### Build the image

Needs [Packer](https://developer.hashicorp.com/packer/install) and a
DigitalOcean API token with write scope. The image is built from this repo's
**committed HEAD** (a `git archive`), so commit first; `.env`, `backups/` and
`.git` never leave your machine.

```sh
cd deploy/digitalocean/packer
export DIGITALOCEAN_API_TOKEN=dop_v1_...
packer init .
packer build .
```

[`armada.pkr.hcl`](./packer/armada.pkr.hcl) spins up a throwaway Ubuntu 24.04
droplet, uploads the archive, runs [`provision.sh`](./packer/provision.sh),
then DigitalOcean's own `90-cleanup.sh` / `99-img_check.sh`, and snapshots as
`armada-stack-<timestamp>`.

### Test it

```sh
doctl compute snapshot list --format ID,Name | grep armada-stack

doctl compute droplet create armada-test \
  --image <snapshot-id> --size s-2vcpu-4gb --region nyc3 \
  --ssh-keys <your-key-fingerprint> --wait

ssh root@<ip>          # armada-setup starts on its own
```

Or pass `--user-data-file` with a `write_files` entry for
`/etc/armada/deploy.env` (`DOMAIN=` / `EMAIL=`) to skip the prompt. Tear down
with `doctl compute droplet delete armada-test`.

### Submit to the Marketplace

The build satisfies DO's
[1-Click requirements](https://docs.digitalocean.com/products/marketplace/): the
cleanup and validation scripts run in the build, no secret is baked, the
firewall is on, and first login explains itself. What remains is DO's vendor
onboarding and listing, which is a manual submission.

## Why not a PaaS deploy button?

App Platform, Render, Railway and Fly's managed tier do not do arbitrary
**UDP** or host **sysctls**, and both are load-bearing:

- `7882/udp` is the voice media path (LiveKit). Without it voice connects and
  then carries no audio.
- `vm.max_map_count=262144` (OpenSearch won't start below it) and
  `net.core.rmem_max=5000000` (LiveKit's media buffer) are host-kernel settings
  a container inherits and cannot set.

## Firewall

`install-host.sh` configures `ufw`. A DigitalOcean **Cloud Firewall** added in
the panel must allow the same inbound set, or it will block what the host
allows:

| Port | Proto | Why |
|---|---|---|
| 22 | tcp | SSH |
| 80 | tcp | HTTP → Caddy (ACME + redirect) |
| 443 | tcp | HTTPS |
| 443 | udp | HTTP/3 |
| 7881 | tcp | LiveKit ICE/TCP fallback |
| 7882 | udp | LiveKit media mux — **voice is silent without it** |

## Not built yet

- A no-DNS `sslip.io` fallback, and a single-wildcard-record option. Both need
  the client to take its endpoints at runtime instead of build time — work in
  the armada repo, not here.
