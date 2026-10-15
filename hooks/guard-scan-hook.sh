#!/bin/sh
# Guard's post-checkout, post-merge and post-rewrite hook. `guard hooks
# install` writes it into ~/.guard/githooks under those three names and points
# git's global core.hooksPath there, so it runs for every repo. A clone runs
# post-checkout, so a fresh clone is scanned before anyone opens it.
#
# `guard scan-checkout` scans what arrived and quarantines malware on a hit;
# on a fresh clone `guard open` warns when the folder would run a task as soon
# as VS Code opens it. Then it runs the hook this one stands in for: the repo's own
# .git/hooks/<name>, and the global hooks path set before Guard's.
#
# Git ignores the exit status of these hooks; this one passes on the status of
# the hook it chains to.

hook=$(basename "$0")
guard='@GUARD@'
[ -x "$guard" ] || guard=$(command -v guard 2>/dev/null) || guard=

# post-rewrite gets git's "<old> <new>" pairs on stdin
input=
if [ "$hook" = post-rewrite ]; then
    input=$(cat; echo .)
    input=${input%.}
fi

if [ -n "$guard" ]; then
    root=$(git rev-parse --show-toplevel 2>/dev/null)
    # a fresh clone (post-checkout from the null commit) gets the VS Code check
    if [ "$hook" = post-checkout ] && [ -n "${1:-}" ] && [ -z "$(printf %s "$1" | tr -d 0)" ] &&
        [ -n "$root" ] && ! "$guard" open "$root" >/dev/null 2>&1; then
        printf '\n\033[31m[GUARD] WARNING: %s runs a task as soon as VS Code opens it.\n' "$root" >&2
        printf '[GUARD] DO NOT OPEN THIS FOLDER IN VS CODE. Check it with: guard scan "%s"\033[0m\n\n' "$root" >&2
    fi
    printf '%s' "$input" | "$guard" scan-checkout "$hook" "$@"
else
    printf '\033[31m[GUARD] the guard binary is missing; %s was not scanned. Reinstall Guard.\033[0m\n' "$hook" >&2
fi

# the hooks a global core.hooksPath hides from git
here=$(cd "$(dirname "$0")" && pwd -P)
prev=$(git config --global --path --get guard.previousHooksPath 2>/dev/null)
repo_hooks="$(git rev-parse --git-common-dir 2>/dev/null)/hooks"
for dir in "$prev" "$repo_hooks"; do
    [ -n "$dir" ] && [ -x "$dir/$hook" ] || continue
    [ "$(cd "$dir" && pwd -P)" = "$here" ] && continue
    printf '%s' "$input" | "$dir/$hook" "$@" || exit $?
done
exit 0
