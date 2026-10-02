#!/usr/bin/env bash
# Install perch as a sandboxed systemd service.
#
#   curl -fsSLO https://github.com/TheChimpions/perch-watchtower/releases/latest/download/install.sh
#   less install.sh                     # read it first; it runs as root
#   sudo bash install.sh
#
# Options:
#   --version vX.Y.Z   install a specific release (default: latest)
#   --from-source      build with the local cargo instead of downloading
#   --operator USER    add USER to the perch group so it can run `perch maint`
#                      (default: the user who invoked sudo)
#
# Safe to re-run: it upgrades the binary and unit, and never touches an existing
# /etc/perch/config.toml or /etc/perch/env. It does not start the service --
# that happens once you have a config that passes --check-config.
set -euo pipefail

REPO="${PERCH_REPO:-TheChimpions/perch-watchtower}"
VERSION="latest"
FROM_SOURCE=0
OPERATOR="${SUDO_USER:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --from-source) FROM_SOURCE=1; shift ;;
    --operator) OPERATOR="$2"; shift 2 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo bash install.sh)"
[ "$(uname -s)" = "Linux" ] || die "perch installs as a systemd service on Linux"
command -v systemctl >/dev/null || die "systemd is required"

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- 1. Get a binary ----------------------------------------------------------

if [ "$FROM_SOURCE" -eq 1 ]; then
  ROOT="$(cd "$HERE/.." && pwd)"
  [ -f "$ROOT/Cargo.toml" ] || die "--from-source must be run from a perch checkout"
  BUILDER="${SUDO_USER:-root}"
  say "building from source in $ROOT as $BUILDER"
  # Build as the invoking user, not root: cargo's cache and target/ belong to them.
  sudo -u "$BUILDER" -H bash -lc "cd '$ROOT' && cargo build --release --locked"
  BIN="$ROOT/target/release/perch"
  SRC="$ROOT"
else
  case "$(uname -m)" in
    x86_64) TARGET="x86_64-unknown-linux-musl" ;;
    aarch64|arm64) TARGET="aarch64-unknown-linux-musl" ;;
    *) die "no prebuilt binary for $(uname -m); use --from-source" ;;
  esac
  if [ "$VERSION" = "latest" ]; then
    BASE="https://github.com/$REPO/releases/latest/download"
  else
    BASE="https://github.com/$REPO/releases/download/$VERSION"
  fi
  ASSET="perch-$TARGET.tar.gz"
  say "downloading $ASSET ($VERSION)"
  curl -fsSL "$BASE/$ASSET" -o "$WORK/$ASSET"
  curl -fsSL "$BASE/SHA256SUMS" -o "$WORK/SHA256SUMS"
  # A download that does not match the published checksum is never installed.
  (cd "$WORK" && grep " $ASSET\$" SHA256SUMS | sha256sum -c --quiet -) \
    || die "checksum mismatch for $ASSET"
  tar -xzf "$WORK/$ASSET" -C "$WORK"
  SRC="$WORK/perch-$TARGET"
  BIN="$SRC/perch"
fi

[ -x "$BIN" ] || die "no binary at $BIN"

# --- 2. Service account -------------------------------------------------------

if ! id perch >/dev/null 2>&1; then
  say "creating system user perch (no shell, no home)"
  useradd --system --user-group --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin perch
fi
if [ -n "$OPERATOR" ] && [ "$OPERATOR" != "root" ]; then
  if id -nG "$OPERATOR" | tr ' ' '\n' | grep -qx perch; then :; else
    say "adding $OPERATOR to the perch group (for perch maint; log in again to take effect)"
    usermod -aG perch "$OPERATOR"
  fi
fi

# --- 3. Files -----------------------------------------------------------------

say "installing /usr/local/bin/perch"
install -m 0755 "$BIN" /usr/local/bin/perch

install -d -m 0750 -o root -g perch /etc/perch
if [ ! -f /etc/perch/config.toml ]; then
  say "writing starter config /etc/perch/config.toml (from examples/1-standalone.toml)"
  install -m 0640 -o root -g perch "$SRC/examples/1-standalone.toml" /etc/perch/config.toml
  install -m 0644 "$SRC/config.example.toml" /etc/perch/config.example.toml
else
  say "keeping existing /etc/perch/config.toml"
fi
if [ ! -f /etc/perch/env ]; then
  say "writing /etc/perch/env (root only, 0600) -- put your secrets here"
  umask 077
  cat > /etc/perch/env <<'EOF'
# Read by systemd as root before perch starts; perch itself cannot read this file.
# Referenced from config.toml as "env:NAME".
PAGERDUTY_INTEGRATION_KEY=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
HEARTBEAT_URL=
EOF
  chmod 0600 /etc/perch/env
fi

# State lives in /var/lib/perch (created by systemd on first start, mode 0750).
# maint/ is setgid and group-writable so operators can declare maintenance and
# perch can clear it when the window ends.
install -d -m 0750 -o perch -g perch /var/lib/perch
install -d -m 2770 -o perch -g perch /var/lib/perch/maint

say "installing /etc/systemd/system/perch.service"
install -m 0644 "$SRC/perch.service" /etc/systemd/system/perch.service
systemctl daemon-reload

# --- 4. Next steps ------------------------------------------------------------

cat <<EOF

perch $(/usr/local/bin/perch --version | awk '{print $2, $3}') is installed. It is not running yet.

  1. Edit /etc/perch/config.toml   -- the validator(s) to watch
     Every option is documented in /etc/perch/config.example.toml.
  2. Edit /etc/perch/env           -- Telegram / PagerDuty / heartbeat secrets
  3. Check it, with the secrets loaded the way systemd will load them:
       sudo bash -c 'set -a; . /etc/perch/env; perch --check-config'
       sudo bash -c 'set -a; . /etc/perch/env; perch test-notify'
     test-notify opens a real PagerDuty incident and resolves it; --quiet pages nobody.
  4. Start it:
       sudo systemctl enable --now perch
       journalctl -u perch -f
  5. Day to day (log in again first, for the perch group):
       perch status
       perch maint restart

EOF
if systemctl is-active --quiet perch; then
  say "perch was already running; restarting onto the new binary"
  systemctl restart perch
fi
