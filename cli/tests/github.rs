//! `guard github check`: the force-push watchdog, against real git repos with
//! a local bare repository standing in for GitHub.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::*;
use serde_json::Value;

/// A remote with `main`, a developer clone under the watch root, an attacker
/// clone outside it, and a private git config for all of them.
struct World {
    t: Tmp,
}

impl World {
    fn new(tag: &str) -> World {
        let w = World { t: Tmp::new(tag) };
        fs::write(w.t.join("gitconfig"), "").unwrap();
        w.git(&w.t.path, &["init", "-q", "--bare", "-b", "main", "remote.git"]);
        w.clone_to("seed");
        let seed = w.t.join("seed");
        w.commit(&seed, "a.txt", "one");
        w.commit(&seed, "a.txt", "two");
        w.git(&seed, &["push", "-q", "origin", "HEAD:main"]);
        fs::create_dir_all(w.t.join("root")).unwrap();
        w.clone_to("root/proj");
        w.clone_to("attacker");
        w
    }

    fn git_cmd(&self, dir: &Path, args: &[&str]) -> Command {
        let mut c = Command::new("git");
        c.current_dir(dir).args(args);
        c.env("GIT_CONFIG_GLOBAL", self.t.join("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com");
        c
    }

    fn git(&self, dir: &Path, args: &[&str]) -> String {
        let o = self.git_cmd(dir, args).output().unwrap();
        assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }

    fn clone_to(&self, name: &str) {
        self.git(&self.t.path, &["clone", "-q", "remote.git", name]);
    }

    fn commit(&self, dir: &Path, file: &str, body: &str) -> String {
        fs::write(dir.join(file), body).unwrap();
        self.git(dir, &["add", "-A"]);
        self.git(dir, &["commit", "-q", "-m", body]);
        self.git(dir, &["rev-parse", "HEAD"])
    }

    /// The remote's tip of a branch.
    fn tip(&self, branch: &str) -> String {
        self.git(&self.t.join("remote.git"), &["rev-parse", branch])
    }

    /// A normal push from the seed clone.
    fn push(&self, body: &str) -> String {
        let seed = self.t.join("seed");
        self.git(&seed, &["pull", "-q", "--ff-only", "origin", "main"]);
        let sha = self.commit(&seed, "a.txt", body);
        self.git(&seed, &["push", "-q", "origin", "HEAD:main"]);
        sha
    }

    /// Rewrites `main` from the attacker clone: drops the last commit and
    /// adds a payload on top, then force-pushes.
    fn force_push(&self) -> String {
        let a = self.t.join("attacker");
        self.git(&a, &["fetch", "-q", "origin"]);
        self.git(&a, &["reset", "-q", "--hard", "origin/main~1"]);
        let sha = self.commit(&a, "evil.js", "payload");
        self.git(&a, &["push", "-q", "-f", "origin", "HEAD:main"]);
        sha
    }

    fn home(&self) -> PathBuf {
        self.t.join("home")
    }

    fn check(&self) -> Out {
        guard(&["github", "check", &s(&self.t.join("root"))])
            .home(&self.home())
            .env("GIT_CONFIG_GLOBAL", self.t.join("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .run()
    }

    fn alerts(&self) -> Vec<Value> {
        fs::read_to_string(self.home().join("alerts.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn proj_refs(&self) -> String {
        self.git(&self.t.join("root/proj"), &["for-each-ref", "--format=%(refname) %(objectname)", "refs/guard"])
    }
}

#[test]
fn force_push_on_main_is_restored() {
    let w = World::new("restore");
    assert_eq!(w.check().code, 0, "first pass records the tip");
    let good = w.push("three");
    let o = w.check();
    assert_eq!(o.code, 0, "{}", o.shown_all());
    assert!(w.alerts().is_empty(), "a normal push is not an alert");

    let bad = w.force_push();
    assert_eq!(w.tip("main"), bad);
    let o = w.check();
    assert_eq!(o.code, 0, "{}", o.shown_all());
    assert_eq!(w.tip("main"), good, "main is back where it was");
    assert!(o.stdout.contains("ALERT [force-push]"), "{}", o.stdout);

    let alerts = w.alerts();
    assert_eq!(alerts.len(), 1);
    let f = &alerts[0]["findings"][0];
    assert_eq!(alerts[0]["kind"], "force-push");
    assert_eq!(f["status"], "restored");
    assert_eq!(f["branch"], "main");
    assert_eq!(f["good"].as_str(), Some(good.as_str()));
    assert_eq!(f["rewritten"].as_str(), Some(bad.as_str()));
    // the attacker's commit is kept for inspection
    let refs = w.proj_refs();
    let evidence = f["evidence"].as_str().unwrap();
    assert!(refs.contains(&format!("{evidence} {bad}")), "{refs}");

    // nothing more to do on the next pass
    let o = w.check();
    assert_eq!(o.code, 0);
    assert_eq!(w.alerts().len(), 1);
    assert_eq!(w.tip("main"), good);
}

#[test]
fn feature_branches_may_be_force_pushed() {
    let w = World::new("feature");
    let a = w.t.join("attacker");
    w.git(&a, &["checkout", "-q", "-b", "feature"]);
    w.commit(&a, "f.txt", "wip");
    w.git(&a, &["push", "-q", "origin", "feature"]);
    assert_eq!(w.check().code, 0);
    w.git(&a, &["commit", "-q", "--amend", "-m", "wip 2"]);
    w.git(&a, &["push", "-q", "-f", "origin", "feature"]);
    let amended = w.tip("feature");
    assert_eq!(w.check().code, 0);
    assert_eq!(w.tip("feature"), amended, "a PR branch rebase is left alone");
    assert!(w.alerts().is_empty());
}

#[test]
fn a_rewrite_seen_long_after_the_last_check_is_reported_not_rolled_back() {
    let w = World::new("stale");
    assert_eq!(w.check().code, 0);
    // pretend the last good check was a week ago
    let state = w.home().join("github-watch.json");
    let mut v: Value = serde_json::from_str(&fs::read_to_string(&state).unwrap()).unwrap();
    for (_, e) in v.as_object_mut().unwrap() {
        e["checked"] = Value::from(1_000_000_000u64);
    }
    fs::write(&state, v.to_string()).unwrap();
    let bad = w.force_push();
    let o = w.check();
    assert_eq!(o.code, 1, "{}", o.shown_all());
    assert_eq!(w.tip("main"), bad, "work this machine never saw is not rolled back");
    assert_eq!(w.alerts()[0]["findings"][0]["status"], "not-restored-too-old");
    assert!(w.proj_refs().contains("refs/guard/good-before/origin/main"));
    // from here on the new history is what Guard trusts
    assert_eq!(w.check().code, 0);
    assert_eq!(w.alerts().len(), 1);
}

#[test]
fn a_failed_restore_is_reported_once_and_retried() {
    let w = World::new("denied");
    let remote = w.t.join("remote.git");
    assert_eq!(w.check().code, 0);
    let bad = w.force_push();
    // the restore is itself a force push: refuse it, as a protected branch would
    w.git(&remote, &["config", "receive.denyNonFastForwards", "true"]);
    let o = w.check();
    assert_eq!(o.code, 1, "{}", o.shown_all());
    assert_eq!(w.tip("main"), bad);
    assert_eq!(w.alerts()[0]["findings"][0]["status"], "restore-failed");
    // the same rewrite isn't reported again while the retry keeps failing
    assert_eq!(w.check().code, 0);
    assert_eq!(w.alerts().len(), 1);
    // once the push goes through, the retry restores it
    w.git(&remote, &["config", "receive.denyNonFastForwards", "false"]);
    assert_eq!(w.check().code, 0);
    assert_ne!(w.tip("main"), bad);
    assert_eq!(w.alerts().len(), 2);
    assert_eq!(w.alerts()[1]["findings"][0]["status"], "restored");
}

#[test]
fn the_restore_only_lands_on_the_rewrite_it_saw() {
    // two pushes race: Guard saw rewrite A, but someone has already moved
    // main again; --force-with-lease refuses to overwrite that
    let w = World::new("lease");
    assert_eq!(w.check().code, 0);
    w.force_push();
    // fetch A into Guard's view without restoring, then move main on
    let proj = w.t.join("root/proj");
    w.git(&proj, &["fetch", "-q", "origin", "+refs/heads/main:refs/guard/seen/origin/main"]);
    let a = w.t.join("attacker");
    let later = w.commit(&a, "b.txt", "later");
    w.git(&a, &["push", "-q", "origin", "HEAD:main"]);
    // Guard's pass sees the newest tip (it asks the remote first), so it
    // restores over that one, with the lease set to it
    let o = w.check();
    assert_eq!(o.code, 0, "{}", o.shown_all());
    assert_ne!(w.tip("main"), later);
    assert_eq!(w.alerts()[0]["findings"][0]["rewritten"].as_str(), Some(later.as_str()));
}

#[test]
fn usage() {
    assert_eq!(guard(&["github"]).run().code, 2);
    assert_eq!(guard(&["github", "watch", "--interval", "x"]).run().code, 2);
}
