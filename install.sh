#!/bin/sh
# Installs the latest version of Armada Stack on your server.
#
#   curl -fsSL https://armada.buzz/install.sh | sudo sh
#
# It's safe to run this script multiple times (eg to upgrade).
#
# This is a long-ass script with a bunch of Python code in it. The reason
# is because Armada releases are deployed on Nostr itself (decentralized
# releases / file storage!) so there is some complexity. We need to fetch
# data from Nostr (WebSockets) and verify Nostr signatures, neither of
# which can be done with basic commands. In the end it just puts a
# precompiled Rust binary on your system and sets up systemd.
#
# This script will continue to work even if half the Nostr network is
# down. Python is used because Python is installed on most distros by
# default.
#
# If you just want the precompiled binary, you can grab it here:
#   https://gitworkshop.dev/soapbox.pub/armada-stack/releases
#
# (Source code there too^)

set -eu

BIN=/usr/local/bin/armada
CONFIG=/etc/armada/armada.toml
UNIT=/etc/systemd/system/armada.service

say() { printf 'armada: %s\n' "$*" >&2; }
die() { say "$*"; exit 1; }

usage() {
	cat <<'EOF'
Install armada from its latest signed release.

  install.sh [DOMAIN] [--email EMAIL] [--version VERSION]

  DOMAIN             set up a server for this domain, which must already
                     point here. Without it, a fresh install asks for one,
                     and an existing server is upgraded.
  --email EMAIL      give Let's Encrypt an address to write to about the
                     certificate
  --version VERSION  install this release instead of the latest

Run as root: curl -fsSL https://armada.buzz/install.sh | sudo sh
EOF
}

# Do you have Python? If not, it's so over.
find_python() {
	for candidate in python3 python; do
		if command -v "$candidate" >/dev/null 2>&1 &&
			"$candidate" -c 'import sys, ssl; sys.exit(sys.version_info < (3, 6))' >/dev/null 2>&1; then
			echo "$candidate"
			return
		fi
	done
}

# Non-consensual Python
install_python() {
	say "Python 3 isn't installed; installing it to check the release's signature"
	log="$TMP/packages"
	if command -v apt-get >/dev/null 2>&1; then
		{ apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y python3 ca-certificates; } </dev/null >"$log" 2>&1
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y python3 ca-certificates </dev/null >"$log" 2>&1
	elif command -v yum >/dev/null 2>&1; then
		yum install -y python3 ca-certificates </dev/null >"$log" 2>&1
	elif command -v apk >/dev/null 2>&1; then
		apk add --no-cache python3 ca-certificates </dev/null >"$log" 2>&1
	elif command -v pacman >/dev/null 2>&1; then
		pacman -Sy --noconfirm --needed python ca-certificates </dev/null >"$log" 2>&1
	elif command -v zypper >/dev/null 2>&1; then
		zypper --non-interactive install python3 ca-certificates </dev/null >"$log" 2>&1
	else
		die "Install Python 3, then run this again."
	fi || {
		cat "$log" >&2
		die "Couldn't install Python 3. Install it, then run this again."
	}
}

# Grab the latest Armada Stack from Nostr and validate it.
# All those codes are just Nostr signature verification. We're not hacking your server ya weirdos
fetch_release() {
	"$PYTHON" - "$1" "$2" "$3" "$4" <<'PYTHON'
import base64, hashlib, json, os, socket, ssl, struct, sys, time
import urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor

# Soapbox's key: releases signed by anyone else are ignored.
PUBKEY = "781a1527055f74c1f70230f10384609b34548f8ab6a0a6caa74025827f9fdae5"
APP = "armada-stack"
RELAYS = [
    "wss://relay.ditto.pub",
    "wss://relay.dreamith.to",
    "wss://git.shakespeare.diy",
    "wss://relay.ngit.dev",
    "wss://relay.primal.net",
]
# Asked for the binary by its hash when the URL in its release fails.
BLOSSOM = ["https://blossom.ditto.pub", "https://blossom.dreamith.to", "https://blossom.primal.net"]
MAX_BINARY = 256 * 1024 * 1024
MAX_MESSAGE = 8 * 1024 * 1024
TIMEOUT = 10
# How far in the future a release may be dated, as armada allows.
MAX_FUTURE = 15 * 60
# The exit status for "there's nothing newer than what's installed".
NOTHING_NEWER = 3


def log(message):
    print("armada: " + message, file=sys.stderr)


def fail(message):
    log(message)
    sys.exit(1)


# BIP-340 Schnorr signatures on secp256k1, which Nostr events are signed
# with. Verification only, in Jacobian coordinates so each point operation
# needs no modular inverse.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    1,
)


def point_double(p):
    if p is None or p[1] == 0:
        return None
    x, y, z = p
    s = 4 * x * y * y % P
    m = 3 * x * x % P
    x3 = (m * m - 2 * s) % P
    y3 = (m * (s - x3) - 8 * pow(y, 4, P)) % P
    return (x3, y3, 2 * y * z % P)


def point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1z1 = z1 * z1 % P
    z2z2 = z2 * z2 % P
    u1 = x1 * z2z2 % P
    u2 = x2 * z1z1 % P
    s1 = y1 * z2 * z2z2 % P
    s2 = y2 * z1 * z1z1 % P
    if u1 == u2:
        return point_double(p) if s1 == s2 else None
    h = (u2 - u1) % P
    r = (s2 - s1) % P
    h2 = h * h % P
    h3 = h * h2 % P
    u1h2 = u1 * h2 % P
    x3 = (r * r - h3 - 2 * u1h2) % P
    y3 = (r * (u1h2 - x3) - s1 * h3) % P
    return (x3, y3, h * z1 * z2 % P)


def point_mul(p, k):
    result = None
    for bit in bin(k)[2:]:
        result = point_double(result)
        if bit == "1":
            result = point_add(result, p)
    return result


def tagged_hash(tag, data):
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


# An AI wrote this shit and I'm not ashamed to admit it
def schnorr_verify(message, pubkey, signature):
    if len(pubkey) != 32 or len(signature) != 64:
        return False
    x = int.from_bytes(pubkey, "big")
    if x >= P:
        return False
    y_squared = (pow(x, 3, P) + 7) % P
    y = pow(y_squared, (P + 1) // 4, P)
    if y * y % P != y_squared:
        return False
    if y & 1:
        y = P - y
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r >= P or s >= N:
        return False
    e = int.from_bytes(tagged_hash("BIP0340/challenge", signature[:32] + pubkey + message), "big") % N
    point = point_add(point_mul(G, s), point_mul((x, y, 1), (N - e) % N))
    if point is None:
        return False
    x3, y3, z3 = point
    z_inverse = pow(z3, P - 2, P)
    if (y3 * pow(z_inverse, 3, P)) % P & 1:
        return False
    return x3 * z_inverse * z_inverse % P == r


# An event's id is the sha256 of its fields serialized as NIP-01 says, which
# escapes these characters and writes all others as they are.
ESCAPES = {"\n": "\\n", '"': '\\"', "\\": "\\\\", "\r": "\\r", "\t": "\\t", "\b": "\\b", "\f": "\\f"}
# Signers don't all agree about the other control characters, though: those
# using JSON.stringify write them as \u00XX, and go-nostr writes \b and \f
# as they are too. An event's id may be the hash of any of the three. That's
# no weaker: whichever it is, it's a hash of these same fields.
ESCAPINGS = [
    ESCAPES,
    dict(ESCAPES, **{chr(c): "\\u{:04x}".format(c) for c in range(0x20) if chr(c) not in ESCAPES}),
    {c: e for c, e in ESCAPES.items() if c not in "\b\f"},
]


def serialize(event, escapes):
    def string(value):
        if not isinstance(value, str):
            raise TypeError("not a string")
        return '"' + "".join(escapes.get(c, c) for c in value) + '"'

    def integer(value):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("not an integer")
        return str(value)

    tags = event["tags"]
    if not isinstance(tags, list) or not all(isinstance(t, list) for t in tags):
        raise TypeError("tags aren't lists")
    return "[0,{},{},{},[{}],{}]".format(
        string(event["pubkey"]),
        integer(event["created_at"]),
        integer(event["kind"]),
        ",".join("[" + ",".join(string(v) for v in t) + "]" for t in tags),
        string(event["content"]),
    )


def event_is_authentic(event):
    """The event's id is the hash of its contents, and its signature is its
    author's (NIP-01)."""
    try:
        ids = set()
        for escapes in ESCAPINGS:
            ids.add(hashlib.sha256(serialize(event, escapes).encode("utf-8")).hexdigest())
            # Without control characters, every escaping is the same.
            if not any(ord(c) < 0x20 for c in serialize(event, {})):
                break
        event_id = event["id"]
        return event_id in ids and schnorr_verify(
            bytes.fromhex(event_id), bytes.fromhex(event["pubkey"]), bytes.fromhex(event["sig"])
        )
    except (KeyError, TypeError, ValueError):
        return False


class WebSocket:
    """Just enough of RFC 6455 to talk to a Nostr relay."""

    def __init__(self, url):
        parts = urllib.parse.urlsplit(url)
        secure = parts.scheme == "wss"
        host = parts.hostname
        sock = socket.create_connection((host, parts.port or (443 if secure else 80)), timeout=TIMEOUT)
        if secure:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        self.sock = sock
        self.buffer = b""
        key = base64.b64encode(os.urandom(16)).decode()
        path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        self.sock.sendall(
            (
                "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                "Sec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: armada-install\r\n\r\n"
            ).format(path, host, key).encode()
        )
        while b"\r\n\r\n" not in self.buffer:
            if len(self.buffer) > 65536:
                raise OSError("handshake response too long")
            self.fill()
        head, self.buffer = self.buffer.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        if len(lines[0].split()) < 2 or lines[0].split()[1] != "101":
            raise OSError("handshake refused: " + lines[0])
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        if headers.get("sec-websocket-accept") != accept:
            raise OSError("handshake answered with the wrong key")

    def fill(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise OSError("connection closed")
        self.buffer += chunk

    def read(self, count):
        while len(self.buffer) < count:
            self.fill()
        data, self.buffer = self.buffer[:count], self.buffer[count:]
        return data

    def send(self, payload, opcode=1):
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        length = len(payload)
        if length < 126:
            header = struct.pack("!BB", 0x80 | opcode, 0x80 | length)
        elif length < 65536:
            header = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, length)
        else:
            header = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, length)
        mask = os.urandom(4)
        self.sock.sendall(header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def receive(self):
        """The next text message."""
        fragments = []
        while True:
            first, second = self.read(2)
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self.read(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self.read(8))[0]
            if length > MAX_MESSAGE:
                raise OSError("message too large")
            mask = self.read(4) if second & 0x80 else None
            payload = self.read(length)
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            opcode = first & 0x0F
            if opcode == 8:
                raise OSError("connection closed")
            if opcode == 9:
                self.send(payload, 10)
            elif opcode in (0, 1, 2):
                fragments.append(payload)
                if first & 0x80:
                    return b"".join(fragments).decode("utf-8")

    def close(self):
        try:
            self.send(b"", 8)
            self.sock.close()
        except OSError:
            pass


def query(relay, nostr_filter):
    """The events one relay has for the filter, until it says it's sent all
    it has (EOSE) or TIMEOUT passes."""
    events = []
    try:
        ws = WebSocket(relay)
        try:
            ws.send(json.dumps(["REQ", "armada-install", nostr_filter]))
            deadline = time.time() + TIMEOUT
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                ws.sock.settimeout(remaining)
                message = json.loads(ws.receive())
                if not isinstance(message, list) or len(message) < 2 or message[1] != "armada-install":
                    continue
                if message[0] == "EVENT" and len(message) > 2 and isinstance(message[2], dict):
                    events.append(message[2])
                elif message[0] in ("EOSE", "CLOSED"):
                    break
        finally:
            ws.close()
    except (OSError, ValueError) as error:
        log("{} didn't answer: {}".format(relay, error))
    return events


def query_all(nostr_filter):
    """Every authentic event of Soapbox's that any relay has for the filter."""
    with ThreadPoolExecutor(len(RELAYS)) as pool:
        results = pool.map(lambda relay: query(relay, nostr_filter), RELAYS)
    found = {}
    for events in results:
        for event in events:
            if event.get("id") not in found and event.get("pubkey") == PUBKEY and event_is_authentic(event):
                found[event["id"]] = event
    return list(found.values())


def tag(event, name):
    for t in event.get("tags", []):
        if isinstance(t, list) and len(t) > 1 and t[0] == name:
            return t[1]
    return None


def tags(event, name):
    return [t[1] for t in event.get("tags", []) if isinstance(t, list) and len(t) > 1 and t[0] == name]


def version_key(version):
    """1.2.3 as (1, 2, 3), or None for anything that isn't plain numbers."""
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:
        return None


def find_release(wanted):
    """The newest release on the main channel, or the release named
    `wanted`, as its kind-30063 event."""
    events = query_all({"kinds": [30063], "authors": [PUBKEY], "#i": [APP]})
    latest = {}
    for event in events:
        # Relays needn't keep to the filter, so it's checked here too.
        if event.get("kind") != 30063 or APP not in tags(event, "i") or event["created_at"] > time.time() + MAX_FUTURE:
            continue
        d = tag(event, "d")
        # Each version is a replaceable event, so only its newest counts.
        if d and (d not in latest or event["created_at"] > latest[d]["created_at"]):
            latest[d] = event
    candidates = []
    for d, event in latest.items():
        version = tag(event, "version")
        if not version or d != APP + "@" + version:
            continue
        if wanted:
            if version == wanted:
                return event
        elif tag(event, "c") == "main" and version_key(version):
            candidates.append(event)
    if wanted:
        fail("There's no release {} of {}.".format(wanted, APP))
    if not candidates:
        fail("Couldn't find a release of {} signed by Soapbox on any relay.".format(APP))
    return max(candidates, key=lambda event: version_key(tag(event, "version")))


def find_asset(release, platform):
    """The release's kind-3063 file event for `platform`."""
    version = tag(release, "version")
    ids = [t[1] for t in release["tags"] if len(t) > 1 and t[0] == "e"]
    application = "32267:{}:{}".format(PUBKEY, APP)
    for event in query_all({"ids": ids, "kinds": [3063], "authors": [PUBKEY]}):
        # One the release names, not just any file event of Soapbox's.
        if event.get("kind") != 3063 or event["id"] not in ids:
            continue
        if application in tags(event, "a") and platform in tags(event, "f") and tag(event, "version") == version:
            return event
    fail("Release {} has no build for {}.".format(version, platform))


def download(asset, destination):
    sha256 = (tag(asset, "x") or "").lower()
    if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
        fail("The release doesn't give the binary's sha256.")
    size = tag(asset, "size")
    size = int(size) if size and size.isdigit() else None
    urls = [tag(asset, "url")] + ["{}/{}".format(server, sha256) for server in BLOSSOM]
    tried = set()
    for url in urls:
        if not url or not url.startswith("https://") or url in tried:
            continue
        tried.add(url)
        partial = destination + ".part"
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "armada-install"})
            digest = hashlib.sha256()
            total = 0
            with urllib.request.urlopen(request, timeout=60) as response, open(partial, "wb") as out:
                while True:
                    chunk = response.read(1 << 16)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_BINARY:
                        raise OSError("larger than {} bytes".format(MAX_BINARY))
                    digest.update(chunk)
                    out.write(chunk)
            if digest.hexdigest() != sha256:
                log("{} sent a file whose sha256 doesn't match the release's".format(url))
            elif size is not None and total != size:
                log("{} sent {} bytes; the release says {}".format(url, total, size))
            else:
                os.replace(partial, destination)
                return url
        except (OSError, ValueError) as error:
            log("couldn't download {}: {}".format(url, error))
        if os.path.exists(partial):
            os.remove(partial)
    fail("No server had a copy of the binary matching sha256 {}.".format(sha256))


def main():
    platform, wanted, directory, installed = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    release = find_release(wanted)
    version = tag(release, "version")
    log(
        "found {} {}, released {}, signed by Soapbox".format(
            APP, version, time.strftime("%Y-%m-%d", time.gmtime(release["created_at"]))
        )
    )
    # A relay that's slow or kept from answering can leave an older release
    # looking like the newest: never go back unless asked to by version.
    if not wanted and version_key(installed) and version_key(version) < version_key(installed):
        log("armada {} is installed, newer than {}; leaving it".format(installed, version))
        sys.exit(NOTHING_NEWER)
    asset = find_asset(release, platform)
    url = download(asset, os.path.join(directory, "armada"))
    log("downloaded {} and checked its sha256, {}".format(url, tag(asset, "x")))
    with open(os.path.join(directory, "version"), "w") as out:
        out.write(version)


main()
PYTHON
}

write_config() {
	mkdir -p "$(dirname "$CONFIG")"
	(
		umask 077
		{
			echo "storage_dir = \"/var/lib/armada\""
			echo "public_url = \"https://$DOMAIN\""
			echo
			echo "[tls]"
			echo "acme = true"
			if [ -n "$EMAIL" ]; then
				echo "email = \"$EMAIL\""
			fi
		} >"$CONFIG"
	)
	protect_config
	say "wrote $CONFIG; every other setting has a default"
}

# Don't let your mom see your config
protect_config() {
	group=$(id -gn armada)
	chown root:"$group" "$(dirname "$CONFIG")" "$CONFIG"
	chmod 750 "$(dirname "$CONFIG")"
	chmod 640 "$CONFIG"
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

wait_for_https() {
	"$PYTHON" - "$DOMAIN" "$1" <<'PYTHON'
import sys, time, urllib.request
domain, seconds = sys.argv[1], int(sys.argv[2])
deadline = time.time() + seconds
while time.time() < deadline:
    try:
        urllib.request.urlopen("https://{}/".format(domain), timeout=5).close()
        sys.exit(0)
    except Exception:
        time.sleep(3)
sys.exit(1)
PYTHON
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

set_up_server() {
	[ -d /run/systemd/system ] ||
		die "Setting up a server needs systemd. INSTALL.md says how to run armada without it."
	"$PYTHON" -c 'import socket, sys; socket.getaddrinfo(sys.argv[1], 443)' "$DOMAIN" 2>/dev/null ||
		die "$DOMAIN doesn't resolve. Point it at this server first; INSTALL.md explains."

	if ! id armada >/dev/null 2>&1; then
		useradd --system --home-dir /var/lib/armada --shell "$(command -v nologin || echo /bin/false)" armada
		say "created the armada user"
	fi

	if [ -e "$CONFIG" ]; then
		protect_config
		say "keeping the existing $CONFIG"
	else
		write_config
	fi

	tune_udp

	# On a new server there's no unit to enable until it's copied in.
	cp "$TMP/unit" "$UNIT"
	systemctl daemon-reload </dev/null
	systemctl enable armada </dev/null >/dev/null 2>&1
	start_service
}

# Install the unit, (re)start the service, and wait for it to answer at
# https://$DOMAIN/, when there's a domain to ask.
start_service() {
	cp "$TMP/unit" "$UNIT"
	systemctl daemon-reload </dev/null
	systemctl restart armada </dev/null
	if [ -z "$DOMAIN" ]; then
		say "restarted the armada service"
		return
	fi
	say "started the armada service; waiting for https://$DOMAIN/"

	if wait_for_https 120; then
		say "armada is running at https://$DOMAIN/"
		if onion=$("$BIN" --config "$CONFIG" onion 2>/dev/null); then
			say "and over Tor at http://$onion/"
		fi
	else
		say "https://$DOMAIN/ isn't answering yet. Ports 80 and 443 have to be open,"
		say "and the domain has to point here (or at Cloudflare's proxy, in front of here)."
		say "See what armada says with: journalctl -u armada -e"
		exit 1
	fi
}

# Yeah we're parsing toml in bash. nbd
config_domain() {
	sed -n 's|^[[:space:]]*public_url[[:space:]]*=[[:space:]]*"https://\([^/"]*\)/\{0,1\}".*|\1|p' "$CONFIG" | head -n 1
}

valid_domain() {
	case "$1" in
	*[!A-Za-z0-9.-]* | .* | *. | *..*) return 1 ;;
	esac
}

prompt_domain() {
	while :; do
		printf '%s\n%s' "armada: Domain for this server, e.g. armada.example.com" \
			"        (it must already point here; leave blank to install only the binary): " >/dev/tty
		read -r DOMAIN </dev/tty || DOMAIN=
		valid_domain "$DOMAIN" && return
		say "$DOMAIN isn't a domain name"
	done
}

main() {
	DOMAIN=
	EMAIL=
	VERSION=
	while [ $# -gt 0 ]; do
		case "$1" in
		-h | --help)
			usage
			exit 0
			;;
		--email | --version)
			[ $# -ge 2 ] || die "$1 needs a value"
			if [ "$1" = --email ]; then EMAIL=$2; else VERSION=$2; fi
			shift 2
			;;
		--email=*) EMAIL=${1#*=} && shift ;;
		--version=*) VERSION=${1#*=} && shift ;;
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
	*[\"\\\ ]*) die "$EMAIL isn't an email address" ;;
	esac

	[ "$(uname -s)" = Linux ] || die "armada's releases are for Linux."
	case "$(uname -m)" in
	x86_64 | amd64) PLATFORM=linux-x86_64 ;;
	aarch64 | arm64) PLATFORM=linux-aarch64 ;;
	*) die "There's no release for $(uname -m) yet; INSTALL.md says how to build from source." ;;
	esac
	[ "$(id -u)" -eq 0 ] || die "Run this as root, e.g. curl -fsSL https://armada.buzz/install.sh | sudo sh -s -- $DOMAIN"

	if [ -e "$CONFIG" ]; then
		# Moving domains means a new certificate and a new public_url, which
		# is a decision for whoever edits the config, not a rerun.
		existing=$(config_domain)
		if [ -n "$DOMAIN" ] && [ -n "$existing" ] && [ "$DOMAIN" != "$existing" ]; then
			die "$CONFIG is for $existing. To move to $DOMAIN, edit its public_url; to upgrade, run this without a domain."
		fi
	elif [ -z "$DOMAIN" ] && (: </dev/tty) 2>/dev/null; then
		prompt_domain
	fi

	TMP=$(mktemp -d)
	trap 'rm -rf "$TMP"' EXIT

	PYTHON=$(find_python)
	if [ -z "$PYTHON" ]; then
		install_python
		PYTHON=$(find_python)
		[ -n "$PYTHON" ] || die "Installed Python 3, but still can't find it."
	fi

	installed=
	if [ -x "$BIN" ]; then
		installed=$("$BIN" --version 2>/dev/null | sed -n 's/^armada //p') || installed=
	fi
	status=0
	fetch_release "$PLATFORM" "$VERSION" "$TMP" "$installed" || status=$?
	if [ "$status" -eq 3 ]; then
		changed=false
	elif [ "$status" -ne 0 ]; then
		exit "$status"
	else
		version=$(cat "$TMP/version")
		chmod 755 "$TMP/armada"
		[ "$("$TMP/armada" --version)" = "armada $version" ] ||
			die "The downloaded binary doesn't say it's version $version."

		if [ -x "$BIN" ] && cmp -s "$TMP/armada" "$BIN"; then
			changed=false
			say "armada $version is already installed at $BIN"
		else
			changed=true
			mkdir -p "$(dirname "$BIN")"
			rm -f "$BIN.new"
			cp "$TMP/armada" "$BIN.new"
			chmod 755 "$BIN.new"
			mv -f "$BIN.new" "$BIN"
			say "installed armada $version at $BIN"
		fi
	fi
	unit_text >"$TMP/unit"

	if [ -n "$DOMAIN" ]; then
		set_up_server
	elif [ -e "$UNIT" ] && [ -d /run/systemd/system ]; then
		# A server is set up: an upgrade. Leave it be only if nothing changed
		# and it's running.
		if ! $changed && cmp -s "$TMP/unit" "$UNIT" && systemctl is-active --quiet armada </dev/null; then
			return
		fi
		if [ -e "$CONFIG" ]; then
			DOMAIN=$(config_domain)
			id armada >/dev/null 2>&1 && protect_config
		fi
		start_service
	else
		say "to set up a server, run this again with its domain"
	fi
}

main "$@"

# You made it this far, huh?
# What were you expecting to find down here, another easter egg?
