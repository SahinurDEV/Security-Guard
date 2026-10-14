//! Repos the hooks leave alone: Guard's own source tree, which has to hold
//! its IOCs (signatures, docs, test fixtures) and would otherwise be
//! "cleaned" on every push and checkout.
//!
//! Trust comes only from places a cloned repo cannot write:
//! * a configured remote URL pointing at the official repository
//!   (`.git/config` is never part of what a clone or pull brings in);
//! * the per-user allowlist `~/.guard/trusted-repos`: one remote URL or
//!   absolute work-tree path per line, `#` comments.
//!
//! A file inside the repository can never mark it trusted, and trust never
//! skips a repo: it only ignores hits in Guard's own known sample files
//! ([`is_sample`], compiled in). Every other file is scanned and cleaned.

use std::path::Path;
use std::process::{Command, Stdio};

/// owner/name of the official repository
pub const OFFICIAL: &str = "syed-bipul-rahman/security-guard";

/// "https://github.com/Owner/Repo.git", "git@github.com:Owner/Repo",
/// "ssh://git@github.com/owner/repo/" -> Some("owner/repo") for github.com.
pub fn github_slug(url: &str) -> Option<String> {
    let u = url.trim().trim_end_matches('/').to_lowercase();
    let rest = ["https://github.com/", "http://github.com/", "git@github.com:", "ssh://git@github.com/", "git://github.com/"]
        .iter()
        .find_map(|p| u.strip_prefix(p))?;
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    let mut it = rest.split('/');
    let (o, n) = (it.next()?, it.next()?);
    if it.next().is_some() || o.is_empty() || n.is_empty() {
        return None;
    }
    Some(format!("{o}/{n}").to_lowercase())
}

fn remote_urls(repo: &Path) -> Vec<String> {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["config", "--local", "--get-regexp", r"^remote\..*\.url$"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|l| l.split_once(' ').map(|(_, v)| v.trim().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn norm_path(p: &str) -> String {
    p.replace('\\', "/").trim_end_matches('/').to_lowercase()
}

/// Files in Guard's own repo that legitimately carry IOCs (signatures,
/// fixtures, docs). Compiled in: nothing in a repo can extend it.
const SAMPLE_DIRS: &[&str] = &["testdata/", "cli/tests/"];
const SAMPLE_FILES: &[&str] = &[
    "signatures.json",
    "signatures.yaml",
    "README.md",
    "cli/src/scan/remediate.rs",
    "windows/guard-triage.ps1",
    "windows/sysmon-config.xml",
    "windows/temp-registry-forensics.ps1",
    ".github/workflows/installer.yml",
    ".github/workflows/release.yml",
    ".github/workflows/tests.yml",
];

/// Is `rel` (repo-relative) one of the known sample paths? Exact,
/// case-sensitive match; `..` never matches.
pub fn is_sample(rel: &str) -> bool {
    let r = rel.replace('\\', "/");
    let r = r.trim_start_matches("./");
    if r.split('/').any(|c| c == ".." || c.is_empty()) {
        return false;
    }
    SAMPLE_FILES.contains(&r) || SAMPLE_DIRS.iter().any(|d| r.starts_with(d))
}

/// Why `repo` is trusted, or None. Trusted means: hits in [`is_sample`]
/// paths are ignored; nothing else changes.
pub fn trusted(repo: &Path) -> Option<String> {
    let urls = remote_urls(repo);
    if urls.iter().any(|u| github_slug(u).as_deref() == Some(OFFICIAL)) {
        return Some("Guard's own repository (remote is github.com/Syed-Bipul-Rahman/Security-Guard)".into());
    }
    let list = std::fs::read_to_string(crate::util::guard_home().join("trusted-repos")).unwrap_or_default();
    let here = std::fs::canonicalize(repo).map(|p| norm_path(&p.to_string_lossy())).unwrap_or_default();
    for line in list.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let by_url = github_slug(line).is_some_and(|s| urls.iter().any(|u| github_slug(u).as_deref() == Some(s.as_str())))
            || urls.iter().any(|u| u.trim() == line);
        if by_url || (!here.is_empty() && listed_path(line) == here) {
            return Some(format!("listed in ~/.guard/trusted-repos ({line})"));
        }
    }
    None
}

/// Canonicalize a listed path (Windows: `\\?\` prefix, 8.3 names) so it
/// compares equal to the canonical work tree.
fn listed_path(line: &str) -> String {
    std::fs::canonicalize(line).map_or_else(|_| norm_path(line), |p| norm_path(&p.to_string_lossy()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_paths() {
        for p in ["testdata/x/y.js", "cli/tests/push.rs", "README.md", "signatures.json", ".github/workflows/tests.yml", "windows/guard-triage.ps1"] {
            assert!(is_sample(p), "{p}");
        }
        for p in ["cli/src/lib.rs", "src/x.js", "install.sh", "docs/guard.ps1", "readme.md", "x/README.md", "testdata/../src/x.js", ".github/workflows/evil.yml", "cli/testsx/a"] {
            assert!(!is_sample(p), "{p}");
        }
    }

    #[test]
    fn slugs() {
        for u in [
            "https://github.com/Syed-Bipul-Rahman/Security-Guard.git",
            "https://github.com/Syed-Bipul-Rahman/Security-Guard/",
            "git@github.com:Syed-Bipul-Rahman/Security-Guard.git",
            "ssh://git@github.com/syed-bipul-rahman/security-guard",
        ] {
            assert_eq!(github_slug(u).as_deref(), Some(OFFICIAL), "{u}");
        }
        // look-alikes are not the official repo
        assert_ne!(github_slug("https://github.com/evil/Security-Guard").as_deref(), Some(OFFICIAL));
        assert_eq!(github_slug("https://github.com.evil.io/Syed-Bipul-Rahman/Security-Guard"), None);
        assert_eq!(github_slug("https://evil.io/github.com/Syed-Bipul-Rahman/Security-Guard"), None);
        assert_eq!(github_slug("https://github.com/Syed-Bipul-Rahman/Security-Guard/x"), None);
        assert_eq!(github_slug("/tmp/repo.git"), None);
    }
}
