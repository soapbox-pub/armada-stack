# Bake the Armada stack into a DigitalOcean snapshot — the artifact a
# Marketplace 1-Click droplet is made from.
#
#   cd deploy/digitalocean/packer
#   export DIGITALOCEAN_API_TOKEN=dop_v1_...
#   packer init .
#   packer build .
#
# The build spins up a throwaway droplet, uploads THIS repo's committed HEAD,
# runs provision.sh (Docker, the stack, sysctls, firewall, pre-pulled images,
# the first-boot unit and setup prompt), runs DigitalOcean's own image
# validation + cleanup, then snapshots.
# The snapshot carries NO secret and NO operator value — provision.sh leaves the
# domain and every generated key to firstboot.sh — which is the hard requirement
# for passing Marketplace review.
#
# Nothing here depends on a local `../` path: the image pulls relay/broker/push
# from ncontainer.io and builds the client from a git-URL context at first boot.

packer {
  required_plugins {
    digitalocean = {
      version = ">= 1.4.0"
      source  = "github.com/digitalocean/digitalocean"
    }
  }
}

variable "token" {
  type        = string
  default     = "${env("DIGITALOCEAN_API_TOKEN")}"
  sensitive   = true
  description = "DigitalOcean API token. Read from DIGITALOCEAN_API_TOKEN by default."
}

variable "region" {
  type        = string
  default     = "nyc3"
  description = "Region to build the throwaway droplet in. Does not constrain where the snapshot can launch."
}

variable "size" {
  type        = string
  default     = "s-2vcpu-4gb"
  description = "Build droplet size. 4 GB matches the stack's floor and lets the image pre-pull cleanly."
}

# The snapshot name carries a UTC timestamp so repeated builds don't collide.
locals {
  snapshot_name = "armada-stack-${formatdate("YYYY-MM-DD-hhmmss", timestamp())}"
}

source "digitalocean" "armada" {
  api_token     = var.token
  region        = var.region
  size          = var.size
  image         = "ubuntu-24-04-x64"
  ssh_username  = "root"
  snapshot_name = local.snapshot_name

  # DO Marketplace snapshots must be tagged so the review tooling finds them.
  tags = ["marketplace-image"]
}

build {
  sources = ["source.digitalocean.armada"]

  # 1. Upload the stack as a `git archive` of HEAD — the COMMITTED tree only. So
  #    `.env`, backups/ and .git (all untracked or not tree content) never leave
  #    this machine, not even onto the throwaway build droplet, and the image is
  #    exactly a commit: uncommitted edits are not baked. Commit first.
  provisioner "shell-local" {
    inline = ["git -C '${path.root}/../../..' archive --format=tar.gz -o '${path.root}/armada-stack.tgz' HEAD"]
  }

  provisioner "file" {
    source      = "${path.root}/armada-stack.tgz"
    destination = "/tmp/armada-stack.tgz"
  }

  provisioner "shell-local" {
    inline = ["rm -f '${path.root}/armada-stack.tgz'"]
  }

  # 2. Bake: Docker, the stack, host pieces, pre-pulled images. provision.sh is
  #    inside the uploaded tree; run it from there so the one copy is
  #    authoritative.
  provisioner "shell" {
    inline = [
      "mkdir -p /tmp/armada-stack && tar xzf /tmp/armada-stack.tgz -C /tmp/armada-stack && rm /tmp/armada-stack.tgz",
      "bash /tmp/armada-stack/deploy/digitalocean/packer/provision.sh /tmp/armada-stack",
    ]
  }

  # 3. DigitalOcean's own cleanup + validation, fetched at build time. 90-cleanup
  #    strips logs, machine-id, SSH host keys, shell history and the build-time
  #    root password; 99-img_check verifies the image meets Marketplace policy
  #    (no leftover users, cleared logs, etc.) and fails the build if not. These
  #    are DO's canonical scripts, not ours — pinned by running them straight
  #    from the marketplace-partners repo.
  provisioner "shell" {
    environment_vars = ["DEBIAN_FRONTEND=noninteractive"]
    inline = [
      "curl -fsSL -o /tmp/90-cleanup.sh https://raw.githubusercontent.com/digitalocean/marketplace-partners/master/scripts/90-cleanup.sh",
      "curl -fsSL -o /tmp/99-img_check.sh https://raw.githubusercontent.com/digitalocean/marketplace-partners/master/scripts/99-img_check.sh",
      "chmod +x /tmp/90-cleanup.sh /tmp/99-img_check.sh",
      "/tmp/90-cleanup.sh",
      "/tmp/99-img_check.sh",
    ]
  }
}
