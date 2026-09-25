#!/usr/bin/env bash
# Install the host-side pieces that make a server with this stack checkout on
# it set itself up: sysctls, firewall, the boot unit, the `armada-setup`
# command, its first-login hook, and the MOTD. Run as root, from the checkout
# that will stay on the box.
#
# Shared by cloud-init.yml (at first boot) and the DigitalOcean Packer image's
# provision.sh (at bake time), so both paths end up with the same host.
# Idempotent. Writes no secret and no operator value.
set -euo pipefail

STACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$STACK_DIR/deploy/cloud-init"

# ── Host sysctls ─────────────────────────────────────────────────────────────
# Host-kernel settings a container inherits and cannot set (preflight explains
# both): OpenSearch refuses to start below max_map_count, and LiveKit drops
# inbound media under load below rmem_max. firstboot.sh applies them live.
cat > /etc/sysctl.d/99-armada.conf <<'SYSCTL'
vm.max_map_count=262144
net.core.rmem_max=5000000
SYSCTL

# ── Firewall ─────────────────────────────────────────────────────────────────
# 7882/udp is the voice media path: with it closed, voice connects and then
# carries no audio. 443/udp is HTTP/3.
#
# Docker publishes ports through its own iptables chain, which ufw does not
# see, so this governs the host's own services (sshd) rather than the stack —
# the stack's exposure is exactly what docker-compose.yml publishes, which is
# this same set. A provider-level firewall must allow the same ports.
if ! command -v ufw >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y ufw
fi
if command -v ufw >/dev/null 2>&1; then
  for rule in 22/tcp 80/tcp 443/tcp 443/udp 7881/tcp 7882/udp; do
    ufw allow "$rule" >/dev/null
  done
  # Fails inside an unprivileged container (no NET_ADMIN); there the host's
  # own firewall is the one that counts, so warn rather than abort.
  ufw --force enable || echo "warning: could not enable ufw; firewall the host instead"
fi

# ── Boot unit, setup command, login hook ─────────────────────────────────────
# The unit names the stack's path; substitute this checkout's location so
# nothing depends on /opt/armada/stack in particular.
sed "s|/opt/armada/stack|$STACK_DIR|g" "$HERE/armada-firstboot.service" \
  > /etc/systemd/system/armada-firstboot.service
systemctl daemon-reload
systemctl enable armada-firstboot.service

ln -sf "$HERE/armada-setup" /usr/local/bin/armada-setup
chmod +x "$HERE/armada-setup" "$HERE/firstboot.sh"
install -m 0644 "$HERE/armada-login.sh" /etc/profile.d/armada-login.sh

# A deploy.env skeleton if the operator's user-data did not already supply one.
# The example.com placeholders are load-bearing: firstboot.sh refuses them, so
# an unconfigured server waits rather than booting a stack on a domain nobody
# owns.
mkdir -p /etc/armada
if [ ! -f /etc/armada/deploy.env ]; then
  cat > /etc/armada/deploy.env <<'DEPLOYENV'
# Set by `armada-setup`, or edit and run `systemctl start armada-firstboot`.
DOMAIN=example.com
EMAIL=you@example.com

# Optional: build the client from a different repo/ref than the stack's pin.
#ARMADA_BUILD_CONTEXT=https://relay.ngit.dev/<npub>/armada.git#<tag|branch|sha>
DEPLOYENV
  chmod 600 /etc/armada/deploy.env
fi

cat > /etc/motd <<MOTD

  Armada (self-hosted)

    Setup:     armada-setup
    Progress:  tail -f /var/log/armada-firstboot.log
    DNS:       $STACK_DIR/scripts/check-dns.sh
    Update:    $STACK_DIR/scripts/update.sh
    Backup:    $STACK_DIR/scripts/backup.sh
    Stack:     cd $STACK_DIR && docker compose ps

MOTD
