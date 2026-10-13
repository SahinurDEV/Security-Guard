//! Repos the hooks leave alone: Guard's own source tree, which has to hold
//! its IOCs (signatures, docs, test fixtures) and would otherwise be
//! "cleaned" on every push and checkout.
//!
//! Trust comes only from places a cloned repo cannot write:
//! * a configured remote URL pointing at the official repository
//!   (`.git/config` is never part of what a clone or pull brings in);
//! * the per-user allowlist `~/.guard/trusted-repos`: one remote URL or
//!   absolute work-tree path per line, `#` comments.
//! A file inside the repository can never mark it trusted.

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

/// Why `repo` is trusted, or None.
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
