#!/usr/bin/env bash
# install.sh — deploy Guard on a macOS/Linux workstation.
#
#   * copies the guard binary into $GUARD_HOME/bin (from $GUARD_BIN, a cargo
#     build in cli/target/release, or a fresh `cargo build --release`)
#   * installs GLOBAL git hooks (post-checkout/merge/rewrite) so every clone/pull
#     is scanned before you open it, and pre-push so infected pushes are blocked
#   * installs + starts the always-on watcher service (launchd / systemd)
#
# Run this ON EACH developer machine. It is idempotent. Detect+report only.
# Uninstall with:  ./install.sh --uninstall
#
# This does NOT need root for the per-user install (recommended). A machine-wide
# install (--system) needs sudo.

set -euo pipefail

GUARD_HOME="${GUARD_HOME:-$HOME/.guard}"
GUARD_BIN_DIR="$GUARD_HOME/bin"
GUARD="$GUARD_BIN_DIR/guard"
HOOKS_DIR="$GUARD_HOME/githooks"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
OS="$(uname -s)"

uninstall() {
    echo "Uninstalling Guard..."
    case "$OS" in
        Darwin)
            launchctl bootout "gui/$(id -u)/me.syedbipul.guard" 2>/dev/null || \
              launchctl unload "$HOME/Library/LaunchAgents/me.syedbipul.guard.plist" 2>/dev/null || true
            rm -f "$HOME/Library/LaunchAgents/me.syedbipul.guard.plist"
            ;;
        Linux)
            systemctl --user disable --now guard.service 2>/dev/null || true
            rm -f "$HOME/.config/systemd/user/guard.service"
            systemctl --user daemon-reload 2>/dev/null || true
            ;;
    esac
    # restore previous global hooksPath only if it points at ours
    if [ "$(git config --global --get core.hooksPath || true)" = "$HOOKS_DIR" ]; then
        git config --global --unset core.hooksPath || true
    fi
    echo "Removed service + global hook wiring. App/config left in $GUARD_HOME (delete manually if desired)."
    exit 0
}

[ "${1:-}" = "--uninstall" ] && uninstall

echo "==> Installing Guard to $GUARD_HOME"
mkdir -p "$GUARD_BIN_DIR" "$HOOKS_DIR"

# 1. The guard binary
src_bin="${GUARD_BIN:-$SRC_DIR/cli/target/release/guard}"
if [ ! -x "$src_bin" ]; then
    command -v cargo >/dev/null 2>&1 || {
        echo "    no guard binary at $src_bin and no cargo to build one." >&2
        echo "    Set GUARD_BIN to a downloaded release binary, or install Rust (https://rustup.rs)." >&2
        exit 1
    }
    echo "    building guard (cargo build --release)..."
    cargo build --release --locked --manifest-path "$SRC_DIR/cli/Cargo.toml"
    src_bin="$SRC_DIR/cli/target/release/guard"
fi
cp "$src_bin" "$GUARD.tmp" && chmod +x "$GUARD.tmp" && mv -f "$GUARD.tmp" "$GUARD"
echo "    binary -> $GUARD ($("$GUARD" version))"

# 2. Global git hooks
for hook in post-checkout post-merge post-rewrite; do
    cp "$SRC_DIR/hooks/guard-scan-hook.sh" "$HOOKS_DIR/$hook"
    chmod +x "$HOOKS_DIR/$hook"
done
cp "$SRC_DIR/hooks/guard-pre-push.sh" "$HOOKS_DIR/pre-push"
chmod +x "$HOOKS_DIR/pre-push"
# Preserve any existing global hooksPath by chaining is out of scope; warn instead.
existing="$(git config --global --get core.hooksPath || true)"
if [ -n "$existing" ] && [ "$existing" != "$HOOKS_DIR" ]; then
    echo "    NOTE: existing core.hooksPath=$existing will be replaced. Chain manually if needed."
fi
git config --global core.hooksPath "$HOOKS_DIR"
echo "    global git hooks -> $HOOKS_DIR (post-checkout/merge/rewrite, pre-push)"

# 3. Default watcher config (only if absent — don't clobber local edits)
if [ ! -f "$GUARD_HOME/watcher.config.json" ]; then
    GUARD_HOME="$GUARD_HOME" "$GUARD" watch --print-default-config \
        > "$GUARD_HOME/watcher.config.json"
    echo "    default config -> $GUARD_HOME/watcher.config.json (edit watch_roots as needed)"
fi

# 4. Service
case "$OS" in
    Darwin)
        plist="$HOME/Library/LaunchAgents/me.syedbipul.guard.plist"
        mkdir -p "$HOME/Library/LaunchAgents"
        sed -e "s|__GUARD_BIN__|$GUARD|g" \
            -e "s|__GUARD_HOME__|$GUARD_HOME|g" \
            "$SRC_DIR/service/macos/me.syedbipul.guard.plist" > "$plist"
        launchctl bootout "gui/$(id -u)/me.syedbipul.guard" 2>/dev/null || true
        # bootout returns before a running agent has stopped, and bootstrapping
        # it again meanwhile fails ("5: Input/output error"): retry briefly
        for try in 1 2 3 4 5 6 7 8 9 10; do
            launchctl bootstrap "gui/$(id -u)" "$plist" 2>/dev/null && break
            [ "$try" = 10 ] && launchctl bootstrap "gui/$(id -u)" "$plist"
            sleep 1
        done
        launchctl enable "gui/$(id -u)/me.syedbipul.guard" 2>/dev/null || true
        echo "    launchd agent installed + started (RunAtLoad, KeepAlive)"
        ;;
    Linux)
        unit="$HOME/.config/systemd/user/guard.service"
        mkdir -p "$HOME/.config/systemd/user"
        sed -e "s|__GUARD_BIN__|$GUARD|g" \
            -e "s|__GUARD_HOME__|$GUARD_HOME|g" \
            "$SRC_DIR/service/linux/guard.service" > "$unit"
        systemctl --user daemon-reload
        systemctl --user enable --now guard.service
        loginctl enable-linger "$USER" 2>/dev/null || true
        echo "    systemd user service enabled + started (Restart=always, linger on)"
        ;;
    *)
        echo "    Unsupported OS for auto service install: $OS (see service/windows for Windows)"
        ;;
esac

echo "==> Done. Logs: $GUARD_HOME/watcher.log  Alerts: $GUARD_HOME/alerts.jsonl"
echo "    Verify: tail -f $GUARD_HOME/watcher.log"
