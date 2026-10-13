#!/bin/sh
# guard-scan-hook.sh — shared Guard hook body, symlinked/copied to the git hook
# names below. Runs a Guard scan on the repo right after a clone/pull/checkout,
# BEFORE the developer opens the folder in an editor.
#
# Installed as a global git hook (core.hooksPath) so it fires for EVERY repo,
# including freshly cloned ones. On malware it quarantines the infected files
# (reversible). No opt-out.
#
# Wired to: post-checkout, post-merge, post-rewrite  (git has no post-clone, but
# a clone runs a post-checkout, so clones are covered).
#
# Exit status is intentionally 0 (never blocks the git operation); the guard
# raises alerts through the agent + a visible warning, not by failing git.

set -u

# Locate the Guard install (overridable via env)
GUARD_HOME="${GUARD_HOME:-$HOME/.guard}"

# The guard binary: $GUARD_BIN, else the per-user install, else the one on PATH
# GUARD_INSTALLED_BIN is filled in by `guard hooks install` (the binary that installed us)
GUARD_INSTALLED_BIN=""
GUARD="${GUARD_BIN:-}"
if [ -z "$GUARD" ] && [ -n "$GUARD_INSTALLED_BIN" ] && [ -x "$GUARD_INSTALLED_BIN" ]; then
    GUARD="$GUARD_INSTALLED_BIN"
fi
if [ -z "$GUARD" ]; then
    if [ -x "$GUARD_HOME/bin/guard" ]; then
        GUARD="$GUARD_HOME/bin/guard"
    else
        GUARD=$(command -v guard 2>/dev/null) || GUARD=""
    fi
fi

# The repo the hook is running in
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || REPO_ROOT=""

# Guard not installed: still run the displaced hooks (don't break git for anyone)
GUARD_OK=1
[ -n "$GUARD" ] && [ -x "$GUARD" ] || GUARD_OK=0
[ -n "$REPO_ROOT" ] || GUARD_OK=0

# post-rewrite gets "<old> <new>" lines on stdin; keep them for the chained hook
[ "$(basename "$0")" = post-rewrite ] && GUARD_CHAIN_STDIN=$(cat)

hook_name=$(basename "$0")
if [ "$GUARD_OK" = 1 ]; then
log="$GUARD_HOME/hook.log"
mkdir -p "$GUARD_HOME" 2>/dev/null || true
echo "$(date -u +%FT%TZ)  $hook_name  $REPO_ROOT" >> "$log" 2>/dev/null || true

# Scan what arrived (a clone: the whole tree; a checkout/pull: just the
# changed files) and, on a hit, quarantine it - reversible with
# `guard restore <path>`. post-rewrite's "<old> <new>" pairs are passed on.
printf '%s\n' "${GUARD_CHAIN_STDIN:-}" | "$GUARD" scan-checkout "$hook_name" "$@" >>"$log"
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

# a displaced hook's failure is passed on (git ignores post-* exit codes anyway)
guard_chain "$(basename "$0")" "$@"
