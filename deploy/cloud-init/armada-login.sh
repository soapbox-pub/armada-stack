# shellcheck shell=sh
# Sourced from /etc/profile.d/armada-login.sh — installed by install-host.sh.
#
# On an interactive root login to a server that has not been set up yet, run
# armada-setup. A marketplace 1-Click image has no form to collect a domain, so
# the first SSH session is where it is asked for. Once provisioned (or if the
# operator Ctrl-Cs out) this only prints a one-line hint.
if [ "$(id -u)" = 0 ] && [ -t 0 ] && [ ! -f /var/lib/armada/.provisioned ]; then
  if [ -z "${ARMADA_SETUP_OFFERED:-}" ]; then
    export ARMADA_SETUP_OFFERED=1
    armada-setup --if-unconfigured || echo "Armada is not set up yet. Run: armada-setup"
  fi
fi
