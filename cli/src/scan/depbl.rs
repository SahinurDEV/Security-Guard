//! Dependency manifests against the GitHub malware blocklist, as the scanner
//! checks them (port of dep_blocklist.py): only a version inside a flagged
//! range counts, so legit packages that once had a bad release stay quiet.

use std::cmp::Ordering;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use super::py;
use crate::av::pystr;
use crate::pyjson::truthy;

pub struct Blocklist {
    bl: Map<String, Value>,
}

static REQ_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^requirements.*\.txt\n?\z").unwrap());

fn is_npm(base: &str) -> bool {
    matches!(
        base,
        "package.json" | "package-lock.json" | "npm-shrinkwrap.json"
    )
}

fn is_pip(base: &str) -> bool {
    matches!(base, "requirements.txt" | "Pipfile.lock") || REQ_FILE.is_match(base)
}

/// os.path.basename
fn basename(p: &str) -> &str {
    let cut = if cfg!(windows) {
        p.rfind(['/', '\\', ':'])
    } else {
        p.rfind('/')
    };
    cut.map_or(p, |i| &p[i + 1..])
}

/// A decimal digit's value, for any Unicode digit Python's \d accepts:
/// Unicode digits come in runs of ten, 0 through 9.
fn digit_value(c: char) -> u8 {
    if let Some(d) = c.to_digit(10) {
        return d as u8;
    }
    static ND: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d$").unwrap());
    let mut back = 0u32;
    let mut cp = c as u32;
    while cp > 0 {
        match char::from_u32(cp - 1) {
            Some(p) if ND.is_match(p.encode_utf8(&mut [0; 4])) => {
                back += 1;
                cp -= 1;
            }
            _ => break,
        }
    }
    (back % 10) as u8
}

/// An int(...) of a \d+ match, kept as canonical digits so any size compares.
#[derive(PartialEq, Eq, Clone, Debug)]
struct Num(String);

impl Num {
    fn parse(s: &str) -> Num {
        let d: String = s
            .chars()
            .map(|c| char::from(b'0' + digit_value(c)))
            .collect();
        let t = d.trim_start_matches('0');
        Num(if t.is_empty() { "0".into() } else { t.into() })
    }
}

impl Ord for Num {
    fn cmp(&self, o: &Self) -> Ordering {
        self.0.len().cmp(&o.0.len()).then_with(|| self.0.cmp(&o.0))
    }
}

impl PartialOrd for Num {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

type Ver = (Num, Num, Num);

fn parse_ver(v: &str) -> Option<Ver> {
    static V3: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\d+)\.(\d+)\.(\d+)").unwrap());
    static V2: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\d+)\.(\d+)").unwrap());
    static V1: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\d+)").unwrap());
    let zero = || Num("0".into());
    if let Some(c) = V3.captures(v) {
        return Some((Num::parse(&c[1]), Num::parse(&c[2]), Num::parse(&c[3])));
    }
    if let Some(c) = V2.captures(v) {
        return Some((Num::parse(&c[1]), Num::parse(&c[2]), zero()));
    }
    V1.captures(v).map(|c| (Num::parse(&c[1]), zero(), zero()))
}

/// Does `installed` satisfy one advisory range (commas mean AND)?
fn in_range(installed: &str, range: &str) -> bool {
    static CLAUSE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[\s\x1c-\x1f]*(>=|<=|==|=|>|<)[\s\x1c-\x1f]*(.+)").unwrap());
    let rs = pystr::strip(range);
    if matches!(rs, ">= 0" | ">=0" | "*" | "") {
        return true; // the whole package is malicious
    }
    let Some(iv) = parse_ver(installed) else {
        return false; // unknown version: don't claim a match
    };
    for clause in rs.split(',') {
        let Some(m) = CLAUSE.captures(pystr::strip(clause)) else {
            return false;
        };
        let Some(tv) = parse_ver(&m[2]) else {
            return false;
        };
        let ok = match &m[1] {
            ">=" => iv >= tv,
            "<=" => iv <= tv,
            "==" | "=" => iv == tv,
            ">" => iv > tv,
            _ => iv < tv,
        };
        if !ok {
            return false;
        }
    }
    true
}

fn str_of(v: Option<&Value>) -> String {
    v.map(pystr::py_str).unwrap_or_default()
}

/// `(x or {})` items, for a JSON object.
fn items(v: Option<&Value>) -> Vec<(&String, &Value)> {
    match v {
        Some(Value::Object(o)) => o.iter().collect(),
        _ => vec![],
    }
}

fn version_of(meta: &Value) -> String {
    match meta {
        Value::Object(m) => str_of(m.get("version").filter(|v| !v.is_null())),
        _ => String::new(),
    }
}

/// The registry package a package.json entry fetches, as (name, spec). An
/// alias (`"x": "npm:real@1.2"`) installs `real`, not `x`. None for a spec
/// that fetches no registry package (a git repo, URL, local path or
/// workspace): the registry package of that name is never installed.
fn npm_alias(name: &str, spec: &str) -> Option<(String, String)> {
    static NON_REGISTRY: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^(?:git[+:]|github:|gitlab:|bitbucket:|gist:|https?:|file:|link:|workspace:|portal:|patch:|[./~]|[^@/\s:]+/[^/\s]+$)",
        )
        .unwrap()
    });
    let spec = spec.trim();
    let Some(target) = spec.strip_prefix("npm:") else {
        return (!NON_REGISTRY.is_match(spec)).then(|| (name.to_string(), spec.to_string()));
    };
    // the version follows the last @ that isn't a scope's leading @
    Some(match target[1.min(target.len())..].rfind('@') {
        Some(i) => (target[..i + 1].to_string(), target[i + 2..].to_string()),
        None => (target.to_string(), String::new()),
    })
}

fn names(base: &str, content: &str) -> Vec<(String, String)> {
    let mut out = vec![];
    if base == "package.json" {
        let Ok(Value::Object(data)) = serde_json::from_str::<Value>(content) else {
            return out;
        };
        for key in [
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ] {
            for (n, v) in items(data.get(key)) {
                out.extend(npm_alias(n, &pystr::py_str(v)));
            }
        }
    } else if base == "package-lock.json" || base == "npm-shrinkwrap.json" {
        let Ok(Value::Object(data)) = serde_json::from_str::<Value>(content) else {
            return out;
        };
        for (pkgpath, meta) in items(data.get("packages")) {
            if !pkgpath.is_empty() {
                // an alias records the package it really installed as "name"
                let name = match meta.get("name") {
                    Some(Value::String(n)) if !n.is_empty() => n.as_str(),
                    _ => pkgpath.rsplit("node_modules/").next().unwrap_or(pkgpath),
                };
                out.push((name.to_string(), version_of(meta)));
            }
        }
        fn walk(deps: Option<&Value>, out: &mut Vec<(String, String)>) {
            for (n, meta) in items(deps) {
                out.push((n.clone(), version_of(meta)));
                if let Value::Object(m) = meta {
                    walk(m.get("dependencies"), out);
                }
            }
        }
        walk(data.get("dependencies"), &mut out);
    } else if base == "Pipfile.lock" {
        let Ok(Value::Object(data)) = serde_json::from_str::<Value>(content) else {
            return out;
        };
        for sect in ["default", "develop"] {
            for (n, meta) in items(data.get(sect)) {
                out.push((
                    n.clone(),
                    version_of(meta).trim_start_matches('=').to_string(),
                ));
            }
        }
    } else {
        static REQ: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"^([A-Za-z0-9._-]+)[\s\x1c-\x1f]*(?:==[\s\x1c-\x1f]*([^\s\x1c-\x1f;]+))?")
                .unwrap()
        });
        for line in py::splitlines(content) {
            let line = pystr::strip(line);
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                continue;
            }
            if let Some(c) = REQ.captures(line) {
                out.push((
                    c[1].to_string(),
                    c.get(2).map_or("", |m| m.as_str()).to_string(),
                ));
            }
        }
    }
    out
}

impl Blocklist {
    /// $GUARD_DEP_BLOCKLIST when it holds a JSON blocklist, else the snapshot
    /// bundled in the binary. None when neither is usable.
    pub fn load() -> Option<Blocklist> {
        let mut candidates: Vec<Vec<u8>> = vec![];
        if let Some(p) = std::env::var_os("GUARD_DEP_BLOCKLIST").filter(|p| !p.is_empty()) {
            if Path::new(&p).exists() {
                if let Ok(b) = std::fs::read(&p) {
                    candidates.push(b);
                }
            }
        }
        candidates.push(crate::deps::bundled_blocklist());
        for b in candidates {
            let Ok(text) = String::from_utf8(b) else {
                return None;
            };
            match serde_json::from_str::<Value>(&py::universal(text)) {
                Ok(Value::Object(bl)) => return (!bl.is_empty()).then_some(Blocklist { bl }),
                Ok(other) => return truthy(Some(&other)).then_some(Blocklist { bl: Map::new() }),
                Err(_) => continue,
            }
        }
        None
    }

    pub fn is_manifest(rel: &str) -> bool {
        let b = basename(rel);
        is_npm(b) || is_pip(b)
    }

    /// The finding dicts the scanner reports for one manifest.
    pub fn check_manifest(&self, rel: &str, content: &str) -> Vec<Value> {
        let base = basename(rel);
        let eco = if is_npm(base) {
            "npm"
        } else if is_pip(base) {
            "pip"
        } else {
            return vec![];
        };
        let eco_bl = match self.bl.get(eco) {
            Some(Value::Object(m)) if !m.is_empty() => m,
            _ => return vec![],
        };
        let mut out = vec![];
        let mut seen: Vec<(String, String)> = vec![];
        for (name, ver) in names(base, content) {
            let Some(ranges) = eco_bl.get(&name) else {
                continue;
            };
            if seen.contains(&(name.clone(), ver.clone())) {
                continue;
            }
            let ranges: Vec<String> = match ranges {
                Value::Array(a) => a.iter().map(pystr::py_str).collect(),
                other => vec![pystr::py_str(other)],
            };
            if !ranges.iter().any(|r| in_range(&ver, r)) {
                continue;
            }
            seen.push((name.clone(), ver.clone()));
            let shown = if ver.is_empty() {
                "?".to_string()
            } else {
                ver.clone()
            };
            out.push(json!({
                "where": rel, "sig_id": "dep.malware", "severity": "critical",
                "category": "malicious-dependency",
                "desc": format!("malicious dependency '{name}' ({eco}); GitHub-flagged range: {}", ranges.join(", ")),
                "ecosystem": eco, "name": name, "version": shown,
            }));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert!(in_range("", ">= 0"));
        assert!(!in_range("", "< 2.0"));
        assert!(in_range("^1.2.3", ">= 1.0.0, < 2"));
        assert!(!in_range("2.0.0", ">= 1.0.0, < 2"));
        assert!(in_range("1.2", "= 1.2.0"));
        assert!(!in_range("1.0", "~1.0"));
        assert!(in_range(
            "100000000000000000000000.1",
            "> 99999999999999999999999"
        ));
        assert!(in_range("١.٢.٣", "== 1.2.3"));
    }

    #[test]
    fn aliases_check_the_real_package() {
        let a = |n, s| npm_alias(n, s).unwrap();
        assert_eq!(a("x", "^1.2"), ("x".into(), "^1.2".into()));
        assert_eq!(a("x", "latest"), ("x".into(), "latest".into()));
        assert_eq!(a("x", ">=1.0.0 <2"), ("x".into(), ">=1.0.0 <2".into()));
        assert_eq!(
            a("s-0-13", "npm:scheduler@0.13.0"),
            ("scheduler".into(), "0.13.0".into())
        );
        assert_eq!(a("y", "npm:@sc/pkg@~2"), ("@sc/pkg".into(), "~2".into()));
        assert_eq!(a("y", "npm:@sc/pkg"), ("@sc/pkg".into(), String::new()));
        assert_eq!(a("y", "npm:evil"), ("evil".into(), String::new()));
        // fetched from somewhere other than the registry
        for spec in [
            "git+https://github.com/google/closure-net.git#6f48f57",
            "github:mongodb-js/dbx-js-tools#main",
            "mongodb-js/dbx-js-tools",
            "https://example.com/x.tgz",
            "file:../x",
            "./x",
            "workspace:*",
            "link:../x",
        ] {
            assert_eq!(npm_alias("x", spec), None, "{spec}");
        }
        let bl = Blocklist {
            bl: serde_json::from_str(r#"{"npm": {"evil": [">= 0"], "s-0-13": [">= 0"]}}"#).unwrap(),
        };
        let pj =
            r#"{"dependencies": {"nice": "npm:evil@1.0.0", "s-0-13": "npm:scheduler@0.13.0"}}"#;
        let hits = bl.check_manifest("package.json", pj);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0]["name"], "evil");
        let lock = r#"{"packages": {"": {}, "node_modules/nice": {"name": "evil", "version": "1.0.0"},
            "node_modules/s-0-13": {"name": "scheduler", "version": "0.13.0"}}}"#;
        let hits = bl.check_manifest("package-lock.json", lock);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0]["name"], "evil");
    }

    #[test]
    fn manifests() {
        assert!(Blocklist::is_manifest("a/requirements-dev.txt"));
        assert!(Blocklist::is_manifest("Pipfile.lock"));
        assert!(!Blocklist::is_manifest("requirements.txt.bak"));
        assert_eq!(
            names("requirements.txt", "# c\n-r x\nfoo==1.2 ; x\nbar\n"),
            vec![("foo".into(), "1.2".into()), ("bar".into(), String::new())]
        );
    }

    /// test_legacy_engines.py TestDepBlocklist test_parse_ver / test_in_range.
    #[test]
    fn versions_and_ranges_like_dep_blocklist_py() {
        let v = |s: &str| parse_ver(s).map(|(a, b, c)| format!("{}.{}.{}", a.0, b.0, c.0));
        assert_eq!(v("1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(v("^4.5").as_deref(), Some("4.5.0"));
        assert_eq!(v("v7").as_deref(), Some("7.0.0"));
        assert_eq!(v("latest"), None);
        for (inst, rng, want) in [
            ("9.9.9", ">= 0", true),
            ("x", "*", true),
            ("", "", true),
            ("latest", "= 1.0.0", false),
            ("1.1.0", ">= 1.0.0, < 1.2", true),
            ("1.2.0", ">= 1.0.0, < 1.2", false),
            ("1.0.0", "~1.0", false),
            ("1.0.0", "= abc", false),
            ("2.0.0", "> 1.0.0", true),
            ("1.0.0", "<= 1.0.0", true),
            ("1.0.0", "== 1.0.0", true),
        ] {
            assert_eq!(in_range(inst, rng), want, "{inst} {rng}");
        }
    }
}
