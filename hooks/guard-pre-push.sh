#!/bin/sh
# Guard's pre-push hook. `guard hooks install` writes it into ~/.guard/githooks
# and points git's global core.hooksPath there, so it runs for every repo.
#
# It hands git's pre-push input to `guard scan-push`, which scans everything
# the push would send (normal, forced and new branches) and blocks the push on
# malware. Then it runs the pre-push hook this one stands in for: the repo's
# own .git/hooks/pre-push, and the global hooks path set before Guard's.
#
# The push is blocked when Guard finds malware, when the scan can't run, and
# when the guard binary is gone. `git push --no-verify` skips every client
# hook, this one included.

hook=pre-push
guard='@GUARD@'
[ -x "$guard" ] || guard=$(command -v guard 2>/dev/null) || guard=

# git's input, kept byte for byte for each command that reads it
input=$(cat; echo .)
input=${input%.}

if [ -z "$guard" ]; then
    printf '\033[31m[GUARD] PUSH BLOCKED: the guard binary is missing. Reinstall Guard, or\n' >&2
    printf '[GUARD] remove its hooks with: git config --global --unset core.hooksPath\033[0m\n' >&2
    exit 1
fi
printf '%s' "$input" | "$guard" scan-push "$@" || exit 1

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
