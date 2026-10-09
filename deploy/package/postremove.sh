#!/bin/sh
# After the files are gone, for both packages. The armada user and
# /var/lib/armada stay: the relay's events, the blobs and the onion's key are
# the things a reinstall can't get back.
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
