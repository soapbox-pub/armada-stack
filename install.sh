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
APT_SOURCE=/etc/apt/sources.list.d/armada-stack.sources
DNF_REPO=/etc/yum.repos.d/armada-stack.repo
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

# Run quietly, showing the output only if it fails.
quietly() {
	"$@" </dev/null >"$TMP/log" 2>&1 || {
		cat "$TMP/log" >&2
		die "$* failed"
	}
}

install_deb() {
	export DEBIAN_FRONTEND=noninteractive
	# Non-consensual curl
	if ! command -v curl >/dev/null 2>&1; then
		say "installing curl"
		quietly apt-get update
		quietly apt-get install -y curl ca-certificates
	fi
	curl -fsSL -o "$TMP/source" "$PKG/deb/soapbox.pub/armada-stack/source"
	install -m 644 "$TMP/source" "$APT_SOURCE"
	say "installing armada-stack with apt"
	quietly apt-get update
	# An existing config is kept, not asked about.
	quietly apt-get install -y -o Dpkg::Options::=--force-confold armada-stack
	say "armada-stack $(dpkg-query -W -f '${Version}' armada-stack) is installed"
}

install_rpm() {
	curl -fsSL -o "$TMP/repo" "$PKG/rpm/soapbox.pub/armada-stack/repo"
	install -m 644 "$TMP/repo" "$DNF_REPO"
	say "installing armada-stack with dnf"
	# dnf5 won't upgrade what's installed with install.
	if rpm -q armada-stack >/dev/null 2>&1; then
		quietly dnf upgrade -y --refresh armada-stack
	else
		quietly dnf install -y --refresh armada-stack
	fi
	say "armada-stack $(rpm -q --qf '%{VERSION}' armada-stack) is installed"
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
	curl -fsS -o /dev/null --max-time 5 "$1" 2>/dev/null
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
	if onion=$(armada --config "$CONFIG" onion 2>/dev/null); then
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
	x86_64 | amd64 | aarch64 | arm64) ;;
	*) die "There's no release for $(uname -m) yet; INSTALL.md says how to build from source." ;;
	esac
	[ "$(id -u)" -eq 0 ] || die "Run this as root, e.g. curl -fsSL https://armada.buzz/install.sh | sudo sh -s -- $DOMAIN"
	if command -v apt-get >/dev/null 2>&1; then
		# The repository's key is inline in its .sources file, which apt
		# reads only from 2.3.10 (Debian 12, Ubuntu 22.04) on.
		dpkg --compare-versions "$(dpkg-query -W -f '${Version}' apt)" ge 2.3.10 ||
			die "This apt is too old for the armada-stack repository. Upgrade to Debian 12 or Ubuntu 22.04, or install armada by hand as INSTALL.md says."
		PACKAGES=deb
	elif command -v dnf >/dev/null 2>&1; then
		PACKAGES=rpm
	else
		die "There's no apt or dnf here. Install armada by hand, as INSTALL.md says."
	fi

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

	install_$PACKAGES

	if [ ! -d /run/systemd/system ]; then
		say "armada is installed, but running it as a server needs systemd. INSTALL.md says how to run it without."
		return
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
