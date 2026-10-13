//! `guard scan-push` and hooks/guard-pre-push.sh against real git repos.
//! Fixtures are inert: a ".otf" whose body is plain JS text (a disguised
//! dropper by file type, but it does nothing), never a live payload.

mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

use common::*;

const ZERO: &str = "0000000000000000000000000000000000000000";
const FAKE_FONT: &str = "module.exports = function () { return 0; };\n";

/// An empty global git config (Windows has no /dev/null for git to read).
fn empty_gitconfig() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("guard-it-empty-gitconfig-{}", std::process::id()));
    if !p.exists() {
        let _ = fs::write(&p, "");
    }
    p
}

fn git(dir: &Path, args: &[&str]) -> String {
    let o = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", empty_gitconfig())
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .output()
        .expect("git");
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

fn commit(dir: &Path, file: &str, body: &str, msg: &str) -> String {
    write(&dir.join(file), body);
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "--no-verify", "-m", msg]);
    git(dir, &["rev-parse", "HEAD"])
}

/// work/ with one clean commit already on remote.git (main).
fn setup(t: &Tmp) -> (std::path::PathBuf, String) {
    let remote = t.join("remote.git");
    let work = t.join("work");
    fs::create_dir_all(&remote).unwrap();
    fs::create_dir_all(&work).unwrap();
    git(&remote, &["init", "-q", "--bare"]);
    git(&work, &["init", "-q", "-b", "main"]);
    git(&work, &["config", "core.hooksPath", "no-hooks"]);
    git(&work, &["remote", "add", "origin", &s(&remote)]);
    let base = commit(&work, "README.md", "hello\n", "init");
    git(&work, &["push", "-q", "--no-verify", "origin", "main"]);
    (work, base)
}

fn scan_push(t: &Tmp, work: &Path, stdin: &str) -> Out {
    guard(&["scan-push", "origin", "url"])
        .home(&t.join("home"))
        .cwd(work)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(stdin.as_bytes())
        .run()
}

fn line(local: &str, remote: &str) -> String {
    format!("refs/heads/main {local} refs/heads/main {remote}\n")
}

#[test]
fn clean_push_passes() {
    let t = Tmp::new("push-clean");
    let (work, base) = setup(&t);
    let tip = commit(&work, "src/app.js", "console.log('hi');\n", "clean");
    let o = scan_push(&t, &work, &line(&tip, &base));
    assert_eq!(o.code, 0, "{}", o.shown_all());
}

#[test]
fn infected_push_is_blocked() {
    let t = Tmp::new("push-bad");
    let (work, base) = setup(&t);
    let tip = commit(&work, "public/fonts/icons.otf", FAKE_FONT, "fonts");
    let o = scan_push(&t, &work, &line(&tip, &base));
    assert_eq!(o.code, 1, "{}", o.shown_all());
    assert!(o.stderr.contains("PUSH BLOCKED"), "{}", o.stderr);
    assert!(o.stdout.contains("icons.otf"), "{}", o.stdout);
}

#[test]
fn file_removed_again_before_push_is_still_blocked() {
    // the bad blob would still be in the remote's history
    let t = Tmp::new("push-hist");
    let (work, base) = setup(&t);
    commit(&work, "public/fonts/icons.otf", FAKE_FONT, "add");
    fs::remove_file(work.join("public/fonts/icons.otf")).unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "--no-verify", "-m", "rm"]);
    let tip = git(&work, &["rev-parse", "HEAD"]);
    assert_eq!(scan_push(&t, &work, &line(&tip, &base)).code, 1);
}

#[test]
fn force_push_of_rewritten_history_is_blocked() {
    let t = Tmp::new("push-force");
    let (work, _) = setup(&t);
    let old = commit(&work, "a.txt", "a\n", "a");
    git(&work, &["push", "-q", "--no-verify", "origin", "main"]);
    // rewrite: drop the pushed commit, add an infected one on the old base
    git(&work, &["reset", "-q", "--hard", "HEAD~1"]);
    let tip = commit(&work, "public/fonts/icons.otf", FAKE_FONT, "rewrite");
    let o = scan_push(&t, &work, &line(&tip, &old));
    assert_eq!(o.code, 1, "{}", o.shown_all());
    // and an old tip we never had locally (fetched by someone else)
    let o = scan_push(&t, &work, &line(&tip, "1234567890123456789012345678901234567890"));
    assert_eq!(o.code, 1, "{}", o.shown_all());
}

#[test]
fn new_branch_is_blocked() {
    let t = Tmp::new("push-new");
    let (work, _) = setup(&t);
    git(&work, &["fetch", "-q", "origin"]);
    git(&work, &["checkout", "-q", "-b", "feature"]);
    let tip = commit(&work, "public/fonts/icons.otf", FAKE_FONT, "f");
    let o = scan_push(&t, &work, &format!("refs/heads/feature {tip} refs/heads/feature {ZERO}\n"));
    assert_eq!(o.code, 1, "{}", o.shown_all());
}

#[test]
fn branch_delete_and_empty_push_pass() {
    let t = Tmp::new("push-del");
    let (work, base) = setup(&t);
    let o = scan_push(&t, &work, &format!("(delete) {ZERO} refs/heads/old {base}\n"));
    assert_eq!(o.code, 0, "{}", o.shown_all());
    assert_eq!(scan_push(&t, &work, "").code, 0);
}

#[test]
fn fail_closed_when_git_cannot_resolve_the_push() {
    let t = Tmp::new("push-failclosed");
    let (work, base) = setup(&t);
    // an unknown local sha: git can't tell what is pushed -> blocked
    let bogus = "1234567890123456789012345678901234567890";
    let o = scan_push(&t, &work, &line(bogus, &base));
    assert_eq!(o.code, 1, "{}", o.shown_all());
    assert!(o.stderr.contains("could not run"));
}

#[test]
fn guard_own_repo_is_exempt_but_look_alikes_are_not() {
    let t = Tmp::new("push-trust");
    let (work, base) = setup(&t);
    let tip = commit(&work, "public/fonts/icons.otf", FAKE_FONT, "x");
    // a look-alike remote (other owner) gets no pass
    git(&work, &["remote", "add", "up", "https://github.com/evil/Security-Guard.git"]);
    assert_eq!(scan_push(&t, &work, &line(&tip, &base)).code, 1);
    // the official remote URL (set in .git/config, never cloned in) does
    git(&work, &["remote", "set-url", "up", "git@github.com:Syed-Bipul-Rahman/Security-Guard.git"]);
    let o = scan_push(&t, &work, &line(&tip, &base));
    assert_eq!(o.code, 0, "{}", o.shown_all());
    assert!(o.stderr.contains("Guard's own repository"), "{}", o.stderr);
    // or the per-user allowlist
    git(&work, &["remote", "remove", "up"]);
    assert_eq!(scan_push(&t, &work, &line(&tip, &base)).code, 1);
    write(&t.join("home/trusted-repos"), format!("# mine\n{}\n", s(&work)));
    assert_eq!(scan_push(&t, &work, &line(&tip, &base)).code, 0);
}

#[test]
fn block_cleans_the_working_tree() {
    let t = Tmp::new("push-clean-wt");
    let (work, base) = setup(&t);
    let tip = commit(&work, "public/fonts/icons.otf", FAKE_FONT, "x");
    let o = guard(&["scan-push"])
        .home(&t.join("home"))
        .cwd(&work)
        .stdin(line(&tip, &base).as_bytes())
        .run();
    assert_eq!(o.code, 1, "{}", o.shown_all());
    assert!(!work.join("public/fonts/icons.otf").exists(), "{}", o.shown_all());
    assert!(o.stderr.contains("guard restore"));
}

/// The real hook through `git push`: blocked normally and with --force;
/// `--no-verify` skips client-side hooks entirely (documented bypass).
#[cfg(unix)]
#[test]
fn hook_blocks_git_push_and_force_push() {
    let t = Tmp::new("push-hook");
    let (work, _) = setup(&t);
    let hooks = t.join("hooks");
    fs::create_dir_all(&hooks).unwrap();
    let hook = hooks.join("pre-push");
    fs::copy(repo_root().join("hooks/guard-pre-push.sh"), &hook).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    git(&work, &["config", "core.hooksPath", &s(&hooks)]);
    commit(&work, "public/fonts/icons.otf", FAKE_FONT, "x");

    let push = |extra: &[&str]| {
        let mut args = vec!["push", "-q"];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["origin", "main"]);
        Command::new("git")
            .current_dir(&work)
            .args(&args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", empty_gitconfig())
            .env("GUARD_BIN", bin())
            .env("GUARD_HOME", t.join("home"))
                .env("GUARD_COMMUNITY_RULES", "0")
            .output()
            .unwrap()
    };
    assert!(!push(&[]).status.success(), "normal push must be blocked");
    assert!(!push(&["--force"]).status.success(), "force push must be blocked");
    // documented: git never runs pre-push hooks with --no-verify
    assert!(push(&["--no-verify"]).status.success());
}

#[test]
fn commits_only_on_another_remote_are_scanned() {
    // an infected upstream (origin) pushed to a new remote must be blocked,
    // while a new branch on origin itself skips what origin already has
    let t = Tmp::new("push-other-remote");
    let (work, _) = setup(&t);
    let tip = commit(&work, "public/fonts/icons.otf", FAKE_FONT, "x");
    git(&work, &["push", "-q", "--no-verify", "origin", "main"]);
    git(&work, &["fetch", "-q", "origin"]);
    let mirror = t.join("mirror.git");
    fs::create_dir_all(&mirror).unwrap();
    git(&mirror, &["init", "-q", "--bare"]);
    git(&work, &["remote", "add", "mirror", &s(&mirror)]);
    let new = format!("refs/heads/main {tip} refs/heads/main {ZERO}\n");
    let run = |remote: &str| {
        guard(&["scan-push", remote, "url"])
            .home(&t.join("home"))
            .cwd(&work)
                .stdin(new.as_bytes())
            .run()
    };
    assert_eq!(run("mirror").code, 1);
    assert_eq!(run(&s(&mirror)).code, 1, "push to a bare path scans everything");
    // origin already has those commits, but its tip is still infected
    assert_eq!(run("origin").code, 1, "pushing onto an infected branch is blocked");

}

#[test]
fn committing_the_cleanup_unblocks_the_push() {
    let t = Tmp::new("push-cleanup");
    let (work, _) = setup(&t);
    commit(&work, "public/fonts/icons.otf", FAKE_FONT, "x");
    git(&work, &["push", "-q", "--no-verify", "origin", "main"]);
    let infected = git(&work, &["rev-parse", "HEAD"]);
    let on_top = commit(&work, "b.txt", "b\n", "work on top");
    assert_eq!(scan_push(&t, &work, &line(&on_top, &infected)).code, 1);
    // the blocked push already quarantined it from the working tree
    let _ = fs::remove_file(work.join("public/fonts/icons.otf"));
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "--no-verify", "-m", "remove malware"]);
    let clean = git(&work, &["rev-parse", "HEAD"]);
    let o = scan_push(&t, &work, &line(&clean, &infected));
    assert_eq!(o.code, 0, "{}", o.shown_all());
}
