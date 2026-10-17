#!/usr/bin/env bash
# Guard installer (Linux/macOS). Served at https://security.sparktech.agency/guard.sh
#   curl -fsSL https://security.sparktech.agency/guard.sh | sudo bash
#
# Downloads the single `guard` binary for this platform from GitHub Releases,
# verifies its SHA-256, installs it to /usr/local/bin, and sets up the auto-start
# service. HTTPS only.
set -euo pipefail

RELEASES="${GUARD_BASE_URL:-https://github.com/Syed-Bipul-Rahman/Security-Guard/releases/latest/download}"
INSTALL_DIR="${GUARD_INSTALL_DIR:-/usr/local/bin}"
BIN="$INSTALL_DIR/guard"

# --- downloader ---
if command -v curl >/dev/null 2>&1; then DL(){ curl -fsSL -o "$1" "$2"; }; DLO(){ curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then DL(){ wget -qO "$1" "$2"; }; DLO(){ wget -qO- "$1"; }
else echo "need curl or wget" >&2; exit 1; fi

# --- detect platform (asset names: guard-<os>-<arch>) ---
case "$(uname -s)" in
  Linux)  os=linux ;;
  Darwin) os=darwin ;;
  *) echo "Unsupported OS $(uname -s). Windows: use guard.ps1" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=x64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "Unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
platform="${os}-${arch}"
asset="guard-${platform}"

echo "Guard installer: $platform"
if [ "$(id -u)" -ne 0 ]; then
  echo "This installs a system service and needs root. Re-run with sudo:" >&2
  echo "  curl -fsSL https://security.sparktech.agency/guard.sh | sudo bash" >&2
  exit 1
fi

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
echo "Downloading $asset ..."
DL "$tmp/guard" "$RELEASES/$asset"

# verify checksum (fail closed)
if want="$(DLO "$RELEASES/$asset.sha256" 2>/dev/null | awk '{print $1}')" && [ -n "$want" ]; then
  if command -v sha256sum >/dev/null 2>&1; then have="$(sha256sum "$tmp/guard" | awk '{print $1}')";
  else have="$(shasum -a 256 "$tmp/guard" | awk '{print $1}')"; fi
  if [ "$want" != "$have" ]; then
    echo "CHECKSUM MISMATCH (want $want, got $have) - aborting." >&2; exit 1
  fi
  echo "checksum OK"
else
  echo "ERROR: no checksum published for $asset - refusing to install unverified binary." >&2
  exit 1
fi

chmod +x "$tmp/guard"
mkdir -p "$INSTALL_DIR"
mv "$tmp/guard" "$BIN"
echo "installed: $BIN ($("$BIN" version))"

echo "Setting up the auto-start service ..."
"$BIN" install

# git hooks for the developer who ran sudo, not root: pre-push blocks infected
# pushes, and every clone and pull is scanned. They go in that user's
# ~/.guard/githooks and global git config.
echo "Setting up the git hooks ..."
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
  sudo -u "$SUDO_USER" -H env -u GUARD_HOME "$BIN" hooks install || echo "warning: git hooks were not installed" >&2
else
  "$BIN" hooks install || echo "warning: git hooks were not installed" >&2
fi

# macOS only lets the user give the service access to Downloads, Desktop,
# Documents and external disks: open the setting and wait for the switch.
# Skipped without a terminal (CI) or with GUARD_SKIP_PERMISSIONS=1.
if [ "$os" = darwin ] && [ -t 1 ] && [ -z "${GUARD_SKIP_PERMISSIONS:-}" ]; then
  echo "Setting up file access ..."
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    sudo -u "$SUDO_USER" -H env -u GUARD_HOME "$BIN" permissions setup || true
  else
    "$BIN" permissions setup || true
  fi
fi

echo ""
echo "Done. Guard is running and will keep itself updated."
echo "Try:  guard version   |   guard scan .   |   guard triage"
