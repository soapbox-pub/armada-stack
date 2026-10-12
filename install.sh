#!/bin/sh
# Installs the latest version of Armada Stack on your server.
#
#   curl -fsSL https://armada.buzz/install.sh | sudo sh
#
# It's safe to run this script multiple times: run it again to upgrade.
#
# If you just want the precompiled binary, you can grab it here:
#   https://gitworkshop.dev/soapbox.pub/armada-stack/releases
#
# (Source code at https://gitworkshop.dev/soapbox.pub/armada-stack)

set -eu

PKG=https://pkg.soapbox.pub
RELEASES=$PKG/releases/soapbox.pub/armada-stack
APT_SOURCE=/etc/apt/sources.list.d/armada-stack.sources
DNF_REPO=/etc/yum.repos.d/armada-stack.repo
# Where the binary goes without a package, and the unit that runs it there.
BIN=/usr/local/bin/armada
UNIT=/etc/systemd/system/armada.service
# Where the .deb and .rpm put the binary, which their package manager upgrades.
PACKAGE_BIN=/usr/bin/armada
CONFIG=/etc/armada/armada.toml

say() { printf 'armada: %s\n' "$*" >&2; }
die() { say "$*"; exit 1; }

usage() {
	cat <<'EOF'
Install armada, or upgrade it to the latest release.

  install.sh [DOMAIN] [--email EMAIL]

  DOMAIN         set up a server for this domain, which must already point
                 here. Without it, a fresh install asks for one, and an
                 existing server is upgraded.
  --email EMAIL  give Let's Encrypt an address to write to about the
                 certificate

Run as root: curl -fsSL https://armada.buzz/install.sh | sudo sh
EOF
}

# Do you have curl? If not, it's so over.
fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO "$2" "$1"
	else
		die "Install curl, then run this again."
	fi
}

# Whether files $1 and $2 are the same. Minimal Fedora has no cmp.
same() {
	[ -e "$2" ] && [ "$(sha256sum <"$1")" = "$(sha256sum <"$2")" ]
}

# The installed version of armada-stack, or nothing. A package removed but
# not purged still has a version, but isn't installed.
deb_version() {
	[ "$(dpkg-query -W -f '${Status}' armada-stack 2>/dev/null)" = "install ok installed" ] &&
		dpkg-query -W -f '${Version}' armada-stack
}

# rpm -q says "package armada-stack is not installed" on stdout.
rpm_version() {
	rpm -q --qf '%{VERSION}' armada-stack 2>/dev/null
}

# Run quietly, showing the output only if it fails.
quietly() {
	"$@" </dev/null >"$TMP/log" 2>&1 || {
		cat "$TMP/log" >&2
		die "$* failed"
	}
}

# Which way armada is installed here: deb, rpm, or binary.
choose_method() {
	if command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
		# The repository's key is inline in its .sources file, which apt
		# reads only from 2.3.10 (Debian 12, Ubuntu 22.04) on.
		apt=$(dpkg-query -W -f '${Version}' apt 2>/dev/null || true)
		if [ -n "$apt" ] && dpkg --compare-versions "$apt" ge 2.3.10; then
			echo deb
			return
		fi
	elif command -v dnf >/dev/null 2>&1; then
		echo rpm
		return
	fi
	echo binary
}

install_deb() {
	export DEBIAN_FRONTEND=noninteractive
	# Non-consensual curl
	if ! command -v curl >/dev/null 2>&1; then
		say "installing curl"
		quietly apt-get update
		quietly apt-get install -y curl ca-certificates
	fi
	fetch "$PKG/deb/soapbox.pub/armada-stack/source" "$TMP/source"
	if ! same "$TMP/source" "$APT_SOURCE"; then
		cp "$TMP/source" "$APT_SOURCE"
		chmod 644 "$APT_SOURCE"
		say "added the armada-stack repository, $APT_SOURCE"
	fi
	before=$(deb_version) || before=
	say "installing armada-stack with apt"
	quietly apt-get update
	# An existing config is kept, not asked about.
	quietly apt-get install -y -o Dpkg::Options::=--force-confold armada-stack
	report_package "$before" "$(deb_version)"
}

install_rpm() {
	fetch "$PKG/rpm/soapbox.pub/armada-stack/repo" "$TMP/repo"
	if ! same "$TMP/repo" "$DNF_REPO"; then
		cp "$TMP/repo" "$DNF_REPO"
		chmod 644 "$DNF_REPO"
		say "added the armada-stack repository, $DNF_REPO"
	fi
	before=$(rpm_version) || before=
	say "installing armada-stack with dnf"
	if [ -n "$before" ]; then
		quietly dnf upgrade -y --refresh armada-stack
	else
		quietly dnf install -y --refresh armada-stack
	fi
	report_package "$before" "$(rpm_version)"
}

report_package() {
	if [ "$1" = "$2" ]; then
		say "armada-stack $2 is already the latest"
	elif [ -n "$1" ]; then
		say "upgraded armada-stack from $1 to $2"
	else
		say "installed armada-stack $2"
	fi
}

# An armada installed by an earlier install.sh, without a package: its unit
# overrides the package's and runs the old binary.
remove_old_install() {
	[ -e "$UNIT" ] && grep -q "^ExecStart=$BIN " "$UNIT" || return 0
	rm -f "$UNIT" "$BIN"
	systemctl daemon-reload </dev/null
	RESTART=true
	say "removed $BIN and $UNIT, which the package replaces"
}

# The binary from the latest release, at $BIN.
install_binary() {
	[ ! -e "$PACKAGE_BIN" ] ||
		die "$PACKAGE_BIN was installed from a package. Upgrade it the way it was installed."
	fetch "$RELEASES/latest" "$TMP/release.json"
	version=$(tr ',' '\n' <"$TMP/release.json" | sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' | head -n 1)
	[ -n "$version" ] || die "Couldn't find the latest release at $RELEASES/latest."
	name="armada-$version-$PLATFORM"
	installed=
	if [ -x "$BIN" ]; then
		installed=$("$BIN" --version 2>/dev/null | sed -n 's/^armada //p') || installed=
	fi
	if [ "$installed" = "$version" ]; then
		say "armada $version is already the latest"
		return
	fi

	# Each asset on a line of its own, to pick out the binary's sha256.
	sha256=$(tr -d '\n' <"$TMP/release.json" | tr '{}' '\n\n' |
		grep "\"name\": *\"$name\"" | sed -n 's/.*"sha256": *"\([0-9a-f]\{64\}\)".*/\1/p')
	[ -n "$sha256" ] || die "Release $version has no build for $PLATFORM."
	say "downloading armada $version"
	fetch "$RELEASES/download/$version/$name" "$TMP/armada"
	echo "$sha256  $TMP/armada" | sha256sum -c - >/dev/null 2>&1 ||
		die "The download's sha256 doesn't match the release's, $sha256."
	chmod 755 "$TMP/armada"
	[ "$("$TMP/armada" --version)" = "armada $version" ] ||
		die "The downloaded binary doesn't say it's version $version."

	mkdir -p "$(dirname "$BIN")"
	cp "$TMP/armada" "$BIN.new"
	mv -f "$BIN.new" "$BIN"
	RESTART=true
	if [ -n "$installed" ]; then
		say "upgraded armada from $installed to $version at $BIN"
	else
		say "installed armada $version at $BIN"
	fi
}

# What the package does in its scripts, for the binary.
set_up_binary_service() {
	if ! id armada >/dev/null 2>&1; then
		useradd --system --home-dir /var/lib/armada --shell "$(command -v nologin || echo /bin/false)" armada
		say "created the armada user"
	fi
	tune_udp
	unit_text >"$TMP/unit"
	if ! same "$TMP/unit" "$UNIT"; then
		cp "$TMP/unit" "$UNIT"
		systemctl daemon-reload </dev/null
		RESTART=true
	fi
}

# Let the built-in LiveKit have the UDP buffers it asks for: every call's
# media shares one socket, and the kernel's default drops packets under load.
tune_udp() {
	sysctl_file=/etc/sysctl.d/60-armada.conf
	[ -e "$sysctl_file" ] && return
	[ -d /etc/sysctl.d ] || return
	printf '%s\n' "# For the LiveKit built into armada; see install.sh." \
		"net.core.rmem_max = 5000000" "net.core.wmem_max = 5000000" >"$sysctl_file"
	sysctl -q -p "$sysctl_file" </dev/null >/dev/null 2>&1 || true
}

# Devuan users shaking and crying
unit_text() {
	cat <<'EOF'
[Unit]
Description=Armada (web app, relay, Blossom, AV broker)
After=network-online.target
Wants=network-online.target

[Service]
User=armada
Group=armada
ExecStart=/usr/local/bin/armada --config /etc/armada/armada.toml
Restart=on-failure
RestartSec=5
StateDirectory=armada
StateDirectoryMode=0700
# Ports 80 and 443 without root, for [tls] acme.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
# Files it makes are its own: keys, the certificate, the databases.
UMask=0077
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
# Other processes hidden, but not the rest of /proc: the built-in LiveKit
# reads the machine's load from it to report how busy it is.
ProtectProc=invisible
# IP for everything it serves and fetches; netlink for resolving names.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
RemoveIPC=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged
# A call the filter misses fails, rather than killing the service.
SystemCallErrorNumber=EPERM
# A file descriptor per relay connection.
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
}

# Yeah we're parsing toml in sh. nbd
config_domain() {
	[ -e "$CONFIG" ] || return 0
	sed -n 's|^[[:space:]]*public_url[[:space:]]*=[[:space:]]*"https://\([^/"]*\)/\{0,1\}".*|\1|p' "$CONFIG" | head -n 1
}

# Point the config at $DOMAIN: a new one, or the package's, which has
# public_url and email commented out.
configure() {
	if [ ! -e "$CONFIG" ]; then
		mkdir -p "$(dirname "$CONFIG")"
		printf '%s\n' 'storage_dir = "/var/lib/armada"' '# public_url = ""' '' \
			'[tls]' 'acme = true' '# email = ""' >"$CONFIG"
	fi
	url="public_url = \"https://$DOMAIN\""
	if grep -q '^#[[:space:]]*public_url[[:space:]]*=' "$CONFIG"; then
		sed -i "s|^#[[:space:]]*public_url[[:space:]]*=.*|$url|" "$CONFIG"
	else
		# Before any [table], where a top-level key has to be.
		sed -i "1i $url" "$CONFIG"
	fi
	if [ -n "$EMAIL" ]; then
		if grep -q '^#[[:space:]]*email[[:space:]]*=' "$CONFIG"; then
			sed -i "s|^#[[:space:]]*email[[:space:]]*=.*|email = \"$EMAIL\"|" "$CONFIG"
		else
			say "not setting the email: add email = \"$EMAIL\" under [tls] in $CONFIG"
		fi
	fi
	# Don't let your mom see your config
	chown root:"$(id -gn armada)" "$(dirname "$CONFIG")" "$CONFIG"
	chmod 750 "$(dirname "$CONFIG")"
	chmod 640 "$CONFIG"
	RESTART=true
	say "set public_url in $CONFIG to https://$DOMAIN"
}

answers() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsS -o /dev/null --max-time 5 "$1" 2>/dev/null
	else
		wget -q -T 5 -O /dev/null "$1" 2>/dev/null
	fi
}

# Start armada, or restart it if anything changed, and wait for it to answer.
start_service() {
	systemctl enable armada </dev/null >/dev/null 2>&1
	if $RESTART; then
		systemctl restart armada </dev/null
	else
		systemctl start armada </dev/null
	fi
	say "armada is running; waiting for https://$DOMAIN/"
	tries=40
	until answers "https://$DOMAIN/"; do
		tries=$((tries - 1))
		if [ "$tries" -eq 0 ]; then
			say "https://$DOMAIN/ isn't answering yet. Ports 80 and 443 have to be open,"
			say "and the domain has to point here (or at Cloudflare's proxy, in front of here)."
			die "See what armada says with: journalctl -u armada -e"
		fi
		sleep 3
	done
	say "armada is running at https://$DOMAIN/"
	if onion=$("$ARMADA" --config "$CONFIG" onion 2>/dev/null); then
		say "and over Tor at http://$onion/"
	fi
}

valid_domain() {
	case "$1" in
	*[!A-Za-z0-9.-]* | .* | *. | *..*) return 1 ;;
	esac
}

prompt_domain() {
	while :; do
		printf '%s\n%s' "armada: Domain for this server, e.g. armada.example.com" \
			"        (it must already point here; leave blank to install only): " >/dev/tty
		read -r DOMAIN </dev/tty || DOMAIN=
		valid_domain "$DOMAIN" && return
		say "$DOMAIN isn't a domain name"
	done
}

main() {
	DOMAIN=
	EMAIL=
	while [ $# -gt 0 ]; do
		case "$1" in
		-h | --help)
			usage
			exit 0
			;;
		--email)
			[ $# -ge 2 ] || die "$1 needs a value"
			EMAIL=$2
			shift 2
			;;
		--email=*) EMAIL=${1#*=} && shift ;;
		-*) die "unknown option $1; see --help" ;;
		*)
			[ -z "$DOMAIN" ] || die "one domain only; see --help"
			DOMAIN=$1
			shift
			;;
		esac
	done
	valid_domain "$DOMAIN" || die "$DOMAIN isn't a domain name"
	case "$EMAIL" in
	*[!A-Za-z0-9._%+@-]*) die "$EMAIL isn't an email address" ;;
	esac

	[ "$(uname -s)" = Linux ] || die "armada's releases are for Linux."
	case "$(uname -m)" in
	x86_64 | amd64) PLATFORM=linux-x86_64 ;;
	aarch64 | arm64) PLATFORM=linux-aarch64 ;;
	*) die "There's no release for $(uname -m) yet; INSTALL.md says how to build from source." ;;
	esac
	[ "$(id -u)" -eq 0 ] || die "Run this as root, e.g. curl -fsSL https://armada.buzz/install.sh | sudo sh -s -- $DOMAIN"

	# Moving domains means a new certificate, which is a decision for whoever
	# edits the config, not a rerun.
	existing=$(config_domain)
	if [ -n "$existing" ]; then
		if [ -n "$DOMAIN" ] && [ "$DOMAIN" != "$existing" ]; then
			die "$CONFIG is for $existing. To move to $DOMAIN, edit its public_url; to upgrade, run this without a domain."
		fi
	elif [ -z "$DOMAIN" ] && (: </dev/tty) 2>/dev/null; then
		prompt_domain
	fi
	if [ -n "$DOMAIN" ] && [ -z "$existing" ] && command -v getent >/dev/null 2>&1; then
		getent hosts "$DOMAIN" >/dev/null ||
			die "$DOMAIN doesn't resolve. Point it at this server first; INSTALL.md explains."
	fi

	TMP=$(mktemp -d)
	trap 'rm -rf "$TMP"' EXIT
	RESTART=false
	SYSTEMD=false
	[ -d /run/systemd/system ] && SYSTEMD=true

	METHOD=$(choose_method)
	ARMADA=$PACKAGE_BIN
	case "$METHOD" in
	deb) install_deb ;;
	rpm) install_rpm ;;
	binary)
		install_binary
		ARMADA=$BIN
		;;
	esac

	if ! $SYSTEMD; then
		say "armada is installed, but running it as a server needs systemd. INSTALL.md says how to run it without."
		return
	fi
	if [ "$METHOD" = binary ]; then
		set_up_binary_service
	else
		remove_old_install
	fi

	if [ -n "$existing" ]; then
		DOMAIN=$existing
	elif [ -n "$DOMAIN" ]; then
		configure
	else
		say "to set up a server, run this again with its domain"
		return
	fi
	start_service
}

main "$@"

# You made it this far, huh?
# What were you expecting to find down here, another easter egg?
