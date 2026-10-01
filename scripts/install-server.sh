#!/bin/sh
# install-server.sh — one-liner NexusMesh control-plane installer.
#
#   curl -fsSL https://raw.githubusercontent.com/Kodjaoglanian/NetStream/main/scripts/install-server.sh | sudo sh
#
# Optional env:
#   NEXUS_VERSION=v0.1.0     pin a release (default: latest)
#   NEXUS_INSTALL_DIR=/opt   extraction dir (default: /tmp)
set -eu

REPO="Kodjaoglanian/NetStream"
INSTALL_DIR="${NEXUS_INSTALL_DIR:-/tmp}"
VERSION="${NEXUS_VERSION:-latest}"

say() { printf '\033[1;34m[nexus]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[nexus] error:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root (sudo sh ...)"

# --- architecture -------------------------------------------------------
arch="$(uname -m)"
case "$arch" in
    x86_64|amd64)  TARGET="x86_64-unknown-linux-musl" ;;
    aarch64|arm64) TARGET="aarch64-unknown-linux-musl" ;;
    *)             die "unsupported architecture: $arch" ;;
esac
say "detected arch: $arch ($TARGET)"

# --- resolve release ----------------------------------------------------
if [ "$VERSION" = "latest" ]; then
    say "resolving latest release..."
    tag="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
    [ -n "$tag" ] || die "could not resolve latest release tag"
else
    tag="$VERSION"
fi
say "installing NexusMesh $tag"

archive="nexusmesh-${tag}-${TARGET}.tar.gz"
base="https://github.com/$REPO/releases/download/$tag"
work="$(mktemp -d "$INSTALL_DIR/nexusmesh.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# --- download + verify --------------------------------------------------
say "downloading $archive"
curl -fsSL "$base/$archive"      -o "$work/pkg.tar.gz"
curl -fsSL "$base/$archive.sha256" -o "$work/pkg.tar.gz.sha256"
(cd "$work" && sha256sum -c pkg.tar.gz.sha256 >/dev/null) || die "checksum verification failed"
say "checksum verified"

tar -xzf "$work/pkg.tar.gz" -C "$work"

# --- install -------------------------------------------------------------
install -m 0755 "$work/bin/nexus-server" /usr/local/bin/nexus-server
if ! id -u nexus >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin nexus || true
fi
mkdir -p /var/lib/nexus /etc/nexus
chown -R nexus:nexus /var/lib/nexus
chmod 750 /var/lib/nexus

if [ -f "$work/packaging/nexus-server.service" ]; then
    install -m 0644 "$work/packaging/nexus-server.service" /etc/systemd/system/nexus-server.service
else
    cat > /etc/systemd/system/nexus-server.service <<'UNIT'
[Unit]
Description=NexusMesh control plane
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=nexus
EnvironmentFile=-/etc/nexus/server.env
ExecStart=/usr/local/bin/nexus-server serve
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ReadWritePaths=/var/lib/nexus
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
[Install]
WantedBy=multi-user.target
UNIT
fi

systemctl daemon-reload
systemctl enable --now nexus-server
sleep 1
systemctl --no-pager --quiet is-active nexus-server \
    || die "nexus-server failed to start — check: journalctl -u nexus-server"
say "nexus-server is active"

# --- first key -----------------------------------------------------------
key="$(nexus-server issue-key --db /var/lib/nexus/nexus.db --label bootstrap --reusable \
    | grep -o 'nexus_sec_[A-Za-z0-9_-]*' | head -1)"
[ -n "$key" ] || die "failed to mint bootstrap auth key"

pubip="$(curl -fsSL --max-time 4 https://api.ipify.org 2>/dev/null || echo '<SERVER_IP>')"
echo
say "NexusMesh control plane is up."
echo
echo "  HTTP/WS : 0.0.0.0:8080"
echo "  STUN    : 0.0.0.0:3478/udp"
echo "  Health  : http://$pubip:8080/healthz"
echo
echo "  Join a node with:"
echo "  curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/install-agent.sh | \\"
echo "      sudo sh -s -- --server http://$pubip:8080 --authkey $key"
echo
