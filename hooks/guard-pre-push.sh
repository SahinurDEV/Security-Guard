#!/bin/sh
# guard-pre-push.sh - Guard's pre-push gate, installed as the global
# `pre-push` hook (core.hooksPath). git passes <remote-name> <remote-url> as
# arguments and the refs being pushed on stdin; `guard scan-push` scans every
# file the push adds (normal pushes, --force / --force-with-lease, new branches
# and tags) and exits non-zero to BLOCK the push when it finds malware.
#
# Bypass: `git push --no-verify` skips ALL client-side pre-push hooks - git
# itself never runs this file then. Use server-side protection (README "Push
# protection") for a gate that can't be skipped.

set -u

GUARD_HOME="${GUARD_HOME:-$HOME/.guard}"
GUARD="${GUARD_BIN:-}"
if [ -z "$GUARD" ]; then
    if [ -x "$GUARD_HOME/bin/guard" ]; then
        GUARD="$GUARD_HOME/bin/guard"
    elif [ -x "$GUARD_HOME/bin/guard.exe" ]; then
        GUARD="$GUARD_HOME/bin/guard.exe"
    else
        GUARD=$(command -v guard 2>/dev/null) || GUARD=""
    fi
fi

refs=$(cat)

if [ -n "$GUARD" ]; then
    mkdir -p "$GUARD_HOME" 2>/dev/null || true
    echo "$(date -u +%FT%TZ)  pre-push  $(pwd)  ${1:-}" >> "$GUARD_HOME/hook.log" 2>/dev/null || true
    printf '%s\n' "$refs" | "$GUARD" scan-push "$@" || exit 1
else
    printf '[GUARD] guard binary not found; pre-push scan skipped\n' >&2
fi

# --- chain to the hooks Guard displaced (husky, lefthook, pre-commit, ...) ---
# 1) the global core.hooksPath that was set before Guard (saved at install),
# 2) the repo's own .git/hooks/<name> (a global core.hooksPath hides it).
# A repo whose LOCAL config sets core.hooksPath (husky v9) never reaches this
# file at all; `guard hooks status` in that repo warns about it.
guard_chain() {
    _name=$1; shift
    _ours=$(cd "$(dirname "$0")" 2>/dev/null && pwd -P)
    _prev=$(cat "$GUARD_HOME/githooks.prev" 2>/dev/null || true)
    case "$_prev" in "~/"*) _prev="$HOME/${_prev#\~/}" ;; esac
    _common=$(git rev-parse --git-common-dir 2>/dev/null || true)
    for _d in "$_prev" "${_common:+$_common/hooks}"; do
        [ -n "$_d" ] && [ -d "$_d" ] || continue
        [ "$(cd "$_d" && pwd -P)" = "$_ours" ] && continue
        [ -x "$_d/$_name" ] || continue
        if [ -n "${GUARD_CHAIN_STDIN+x}" ]; then
            printf '%s\n' "$GUARD_CHAIN_STDIN" | "$_d/$_name" "$@" || return $?
        else
            "$_d/$_name" "$@" || return $?
        fi
    done
    return 0
}

GUARD_CHAIN_STDIN=$refs
guard_chain pre-push "$@"
