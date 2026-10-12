#!/bin/sh
# After the files are in place, for both packages. dpkg calls this with
# `configure <old version>`, the old version empty on a first install; rpm with
# the number of copies installed, 1 on a first install.
set -e

case "$1" in
    configure) upgrade="${2:+yes}" ;;
    1) upgrade= ;;
    [0-9]*) upgrade=yes ;;
    *) exit 0 ;;
esac

systemd-sysusers armada.conf
# The config can hold secrets, such as a LiveKit node's: readable by armada,
# writable by root.
chown root:armada /etc/armada /etc/armada/armada.toml
chmod 750 /etc/armada
chmod 640 /etc/armada/armada.toml
# In a container the kernel's settings may not be this package's to change.
systemd-sysctl 60-armada.conf 2>/dev/null || true

# Without systemd running (a container, a chroot) there is nothing to tell.
[ -d /run/systemd/system ] || exit 0
systemctl daemon-reload

if [ -n "$upgrade" ]; then
    # Only if it was running: one stopped on purpose stays stopped.
    systemctl try-restart armada.service
    exit 0
fi

# Not started, nor enabled: until public_url is set it would only fail and
# restart, every five seconds.
cat <<'EOF'
armada is installed. Set public_url in /etc/armada/armada.toml, then:

    sudo systemctl enable --now armada

See INSTALL.md for the firewall, and for running behind a reverse proxy.
EOF

# An armada installed by install.sh before the package has its own unit,
# which overrides the package's and still runs /usr/local/bin/armada.
if [ -e /etc/systemd/system/armada.service ]; then
    cat <<'EOF'

/etc/systemd/system/armada.service, from install.sh, overrides the unit this
package installed and runs the old binary. Remove it, and
/usr/local/bin/armada, then run `sudo systemctl daemon-reload && sudo systemctl
restart armada`.
EOF
fi
