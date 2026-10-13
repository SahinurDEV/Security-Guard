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
exit 0
