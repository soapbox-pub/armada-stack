#!/bin/sh
# Package a release binary as a .deb and an .rpm, with nfpm
# (https://nfpm.goreleaser.com). Run from the repository root:
#
#   deploy/package/build.sh VERSION ARCH BINARY OUTDIR
#
# ARCH is x86_64 or aarch64. Writes armada-VERSION-linux-ARCH.deb and .rpm to
# OUTDIR.
set -eu

if [ $# -ne 4 ]; then
    echo "Usage: $0 VERSION ARCH BINARY OUTDIR" >&2
    exit 2
fi
version="$1"
arch="$2"
binary="$3"
outdir="$4"

# nfpm's architectures are Go's; it names them the rpm way itself.
case "$arch" in
    x86_64) nfpm_arch=amd64 ;;
    aarch64) nfpm_arch=arm64 ;;
    *)
        echo "Unknown architecture $arch: use x86_64 or aarch64." >&2
        exit 2
        ;;
esac

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

# deploy/armada.service is written for install.sh, which puts the binary in
# /usr/local/bin; the package puts it in /usr/bin. Its opening comment says
# how to install it by hand, so it's left out, as install.sh leaves it.
sed -n -e '/^\[Unit\]$/,$p' deploy/armada.service | sed 's|/usr/local/bin/armada|/usr/bin/armada|g' > "$stage/armada.service"
if ! grep -qx 'ExecStart=/usr/bin/armada --config /etc/armada/armada.toml' "$stage/armada.service"; then
    echo "deploy/armada.service changed shape; update $0 to match." >&2
    exit 1
fi

cp "$binary" "$stage/armada"
cp LICENSE deploy/package/nfpm.yaml deploy/package/armada.toml deploy/package/*.conf \
    deploy/package/post*.sh deploy/package/pre*.sh "$stage/"

mkdir -p "$outdir"
outdir="$(cd "$outdir" && pwd)"
export ARMADA_VERSION="$version" ARMADA_ARCH="$nfpm_arch"
for packager in deb rpm; do
    (cd "$stage" && nfpm package --packager "$packager" --target "$outdir/armada-$version-linux-$arch.$packager")
done
