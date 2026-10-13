//! `guard hooks install | uninstall | status` and hook chaining, against a
//! private global git config (GIT_CONFIG_GLOBAL) in a scratch dir.

mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

use common::*;

struct Env {
    t: Tmp,
}

impl Env {
    fn new(tag: &str) -> Env {
        let t = Tmp::new(tag);
        fs::create_dir_all(t.join("home")).unwrap();
        write(&t.join("gitconfig"), "");
        Env { t }
    }
    fn gitcfg(&self) -> std::path::PathBuf {
        self.t.join("gitconfig")
    }
    fn guard(&self, args: &[&str]) -> Out {
        guard(args)
            .home(&self.t.join("home/.guard"))
            .env("HOME", self.t.join("home"))
            .env("GIT_CONFIG_GLOBAL", self.gitcfg())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GUARD_HOOKS_NO_SUDO", "1")
            .env_remove("SUDO_USER")
            .run()
    }
    fn git(&self, dir: &Path, args: &[&str]) -> (bool, String) {
        let o = Command::new("git")
            .current_dir(dir)
            .args(args)
            .env("HOME", self.t.join("home"))
            .env("GIT_CONFIG_GLOBAL", self.gitcfg())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GUARD_HOME", self.t.join("home/.guard"))
            .env("GUARD_BIN", bin())
            .env("GUARD_COMMUNITY_RULES", "0")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
            .output()
            .unwrap();
        (o.status.success(), String::from_utf8_lossy(&o.stdout).trim().to_string())
    }
    fn hooks_path(&self) -> String {
        self.git(&self.t.path, &["config", "--global", "--get", "core.hooksPath"]).1
    }
}

fn ours(e: &Env) -> String {
    s(&e.t.join("home/.guard/githooks")).replace('\\', "/")
}

#[test]
fn install_then_uninstall_restores_previous_hooks_path() {
    let e = Env::new("hooks-prev");
    e.git(&e.t.path, &["config", "--global", "core.hooksPath", "/opt/company-hooks"]);
    let o = e.guard(&["hooks", "install"]);
    assert_eq!(o.code, 0, "{}", o.shown_all());
    assert_eq!(e.hooks_path(), ours(&e));
    for h in ["post-checkout", "post-merge", "post-rewrite", "pre-push"] {
        assert!(e.t.join("home/.guard/githooks").join(h).is_file(), "{h}");
    }
    // a reinstall must not record Guard itself as "previous"
    assert_eq!(e.guard(&["hooks", "install"]).code, 0);
    assert_eq!(e.guard(&["hooks", "status"]).code, 0);
    let o = e.guard(&["hooks", "uninstall"]);
    assert_eq!(o.code, 0, "{}", o.shown_all());
    assert_eq!(e.hooks_path(), "/opt/company-hooks");
    assert!(!e.t.join("home/.guard/githooks").exists());
}

#[test]
fn uninstall_unsets_when_there_was_nothing_before() {
    let e = Env::new("hooks-none");
    assert_eq!(e.guard(&["hooks", "status"]).code, 1);
    assert_eq!(e.guard(&["hooks", "install"]).code, 0);
    assert_eq!(e.guard(&["hooks", "uninstall"]).code, 0);
    assert_eq!(e.hooks_path(), "");
    // uninstall again: nothing to do, still fine and quiet
    let o = e.guard(&["hooks", "uninstall"]);
    assert_eq!((o.code, o.stdout.as_str()), (0, ""));
}

#[test]
fn uninstall_leaves_a_foreign_hooks_path_alone() {
    let e = Env::new("hooks-foreign");
    assert_eq!(e.guard(&["hooks", "install"]).code, 0);
    e.git(&e.t.path, &["config", "--global", "core.hooksPath", "/somewhere/else"]);
    assert_eq!(e.guard(&["hooks", "uninstall"]).code, 0);
    assert_eq!(e.hooks_path(), "/somewhere/else");
}

#[test]
fn bad_usage() {
    let e = Env::new("hooks-usage");
    assert_eq!(e.guard(&["hooks"]).code, 2);
    assert_eq!(e.guard(&["hooks", "nope"]).code, 2);
}

/// Guard's hooks run the displaced global hooks and the repo's own
/// .git/hooks (lefthook / pre-commit style), passing stdin and failures on.
#[cfg(unix)]
#[test]
fn hooks_chain_to_previous_and_repo_local_hooks() {
    use std::os::unix::fs::PermissionsExt;
    let e = Env::new("hooks-chain");
    let exec = |p: &Path, body: &str| {
        write(p, body);
        fs::set_permissions(p, fs::Permissions::from_mode(0o755)).unwrap();
    };
    let prev = e.t.join("company-hooks");
    let marks = e.t.join("marks");
    fs::create_dir_all(&marks).unwrap();
    exec(
        &prev.join("pre-push"),
        &format!("#!/bin/sh\ncat > '{}'\n[ -f '{}' ] && exit 1\nexit 0\n", s(&marks.join("prev-pre-push")), s(&marks.join("fail"))),
    );
    e.git(&e.t.path, &["config", "--global", "core.hooksPath", &s(&prev)]);
    assert_eq!(e.guard(&["hooks", "install"]).code, 0);

    let remote = e.t.join("remote.git");
    fs::create_dir_all(&remote).unwrap();
    e.git(&remote, &["init", "-q", "--bare"]);
    let work = e.t.join("work");
    fs::create_dir_all(&work).unwrap();
    e.git(&work, &["init", "-q", "-b", "main"]);
    exec(
        &work.join(".git/hooks/post-checkout"),
        &format!("#!/bin/sh\necho \"$@\" > '{}'\n", s(&marks.join("local-post-checkout"))),
    );
    write(&work.join("a.txt"), "a\n");
    e.git(&work, &["add", "-A"]);
    assert!(e.git(&work, &["commit", "-qm", "a"]).0);
    e.git(&work, &["remote", "add", "origin", &s(&remote)]);
    assert!(e.git(&work, &["push", "-q", "origin", "main"]).0, "clean push passes");
    let got = fs::read_to_string(marks.join("prev-pre-push")).unwrap();
    assert!(got.contains("refs/heads/main"), "previous pre-push got the refs: {got:?}");

    assert!(e.git(&work, &["checkout", "-q", "-b", "x"]).0);
    assert!(marks.join("local-post-checkout").is_file(), "repo-local hook chained");

    // a chained hook's failure still blocks the push
    write(&marks.join("fail"), "");
    write(&work.join("b.txt"), "b\n");
    e.git(&work, &["add", "-A"]);
    e.git(&work, &["commit", "-qm", "b"]);
    assert!(!e.git(&work, &["push", "-q", "origin", "x"]).0);
}
