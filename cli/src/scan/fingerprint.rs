//! Incident signature matching on file content and git diffs (port of
//! fingerprint_matcher.py): literals, combo rules, structural regexes, network
//! IOCs, known dropper names and attack-associated workflow names.

use regex::Regex;
use serde_json::{json, Value};

use super::py;
use super::sigs::{list, opt_str, req_str, str_list, Res};
use crate::av::pystr;

/// Where package managers install dependencies; scanned in full, never pruned.
pub const DEPS_DIR: &str = "node_modules";

pub struct Finding {
    pub where_: String,
    pub sig_id: String,
    pub severity: String,
    pub category: String,
    pub desc: String,
    pub evidence: String,
}

impl Finding {
    fn new(
        where_: &str,
        sig_id: &str,
        severity: &str,
        category: &str,
        desc: &str,
        evidence: &str,
    ) -> Self {
        Finding {
            where_: where_.into(),
            sig_id: sig_id.into(),
            severity: severity.into(),
            category: category.into(),
            desc: desc.into(),
            evidence: evidence.into(),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "where": self.where_, "sig_id": self.sig_id, "severity": self.severity,
            "category": self.category, "desc": self.desc, "evidence": self.evidence,
        })
    }
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {}: {} ({}) \u{2014} {}",
            self.severity.to_uppercase(),
            self.where_,
            self.sig_id,
            self.category,
            self.desc
        )?;
        if !self.evidence.is_empty() {
            write!(f, "  <<{}>>", self.evidence)?;
        }
        Ok(())
    }
}

struct Literal {
    id: String,
    severity: String,
    category: String,
    desc: String,
    value: String,
    applies_to: Vec<String>,
}

struct Combo {
    id: String,
    severity: String,
    category: String,
    desc: String,
    all_of: Vec<String>,
}

struct Rx {
    id: String,
    /// path suffixes or file names the regex is limited to (empty: any file)
    applies_to: Vec<String>,
    severity: String,
    category: String,
    desc: String,
    requires: Option<String>,
    /// a generic rule: it reports only when no other rule of its category
    /// already fired on the same content
    fallback: bool,
    re: Regex,
}

struct Ioc {
    id: String,
    severity: String,
    desc: String,
    value: String,
}

pub struct Matcher {
    literals: Vec<Literal>,
    combos: Vec<Combo>,
    regexes: Vec<Rx>,
    iocs: Vec<Ioc>,
    skip_prefixes: Vec<String>,
    dropper_names: Vec<String>,
    suspicious_workflows: Vec<String>,
}

fn category(v: &Value) -> String {
    opt_str(v, "category").unwrap_or_else(|| "?".into())
}

impl Matcher {
    pub fn new(sig: &Value) -> Res<Matcher> {
        let mut m = Matcher {
            literals: vec![],
            combos: vec![],
            regexes: vec![],
            iocs: vec![],
            skip_prefixes: str_list(sig.get("skip_path_prefixes"))?,
            dropper_names: str_list(sig.get("known_dropper_filenames"))?,
            suspicious_workflows: str_list(sig.get("suspicious_workflow_names"))?,
        };
        for lit in list(sig.get("literals")) {
            let applies = lit
                .get("applies_to")
                .filter(|v| crate::pyjson::truthy(Some(v)));
            m.literals.push(Literal {
                id: req_str(lit, "id")?,
                severity: req_str(lit, "severity")?,
                category: category(lit),
                desc: req_str(lit, "desc")?,
                value: req_str(lit, "value")?,
                applies_to: str_list(applies)?,
            });
        }
        for c in list(sig.get("combo_rules")) {
            m.combos.push(Combo {
                id: req_str(c, "id")?,
                severity: req_str(c, "severity")?,
                category: category(c),
                desc: req_str(c, "desc")?,
                all_of: str_list(c.get("all_of"))?,
            });
        }
        for r in list(sig.get("regexes")) {
            let flags = r.get("flags").map(pystr::py_str).unwrap_or_default();
            let applies = r
                .get("applies_to")
                .filter(|v| crate::pyjson::truthy(Some(v)));
            m.regexes.push(Rx {
                id: req_str(r, "id")?,
                applies_to: str_list(applies)?,
                severity: req_str(r, "severity")?,
                category: category(r),
                desc: req_str(r, "desc")?,
                requires: opt_str(r, "requires").filter(|s| !s.is_empty()),
                fallback: r.get("fallback").and_then(Value::as_bool).unwrap_or(false),
                re: py::compile(&req_str(r, "pattern")?, &flags)?,
            });
        }
        for i in list(sig.get("network_iocs")) {
            m.iocs.push(Ioc {
                id: req_str(i, "id")?,
                severity: req_str(i, "severity")?,
                desc: req_str(i, "desc")?,
                value: req_str(i, "value")?,
            });
        }
        Ok(m)
    }

    /// A skip token is a path component anywhere in `path`.
    pub fn skip(&self, path: &str) -> bool {
        skip_path(&self.skip_prefixes, path)
    }

    fn applies(applies_to: &[String], path: &str) -> bool {
        if applies_to.is_empty() {
            return true;
        }
        let base = pystr::name(path);
        applies_to.iter().any(|a| {
            let short = a.trim_start_matches(['.', '/']);
            path.ends_with(a.as_str())
                || base == short.rsplit('/').next().unwrap_or("")
                || path.ends_with(a.trim_start_matches('.'))
        })
    }

    pub fn scan_content(&self, path: &str, content: &str) -> Vec<Finding> {
        if self.skip(path) {
            return Vec::new();
        }
        self.scan_text(path, content)
    }

    /// scan_content without the skip check, for a caller that already knows
    /// the file is in scope (the tree walk inside node_modules).
    pub fn scan_text(&self, path: &str, content: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        let base = pystr::name(path);
        if self.dropper_names.iter().any(|n| n == base) {
            out.push(Finding::new(
                path,
                "drop.file.name",
                "critical",
                "dropper-file",
                "known dropper filename",
                base,
            ));
        }
        let norm = path.replace('\\', "/");
        let mut seen_wf: Vec<&str> = Vec::new();
        for wf in &self.suspicious_workflows {
            if norm.ends_with(wf.as_str()) && !seen_wf.contains(&wf.as_str()) {
                seen_wf.push(wf);
                out.push(Finding::new(
                    path,
                    "wf.name",
                    "high",
                    "workflow",
                    "attack-associated workflow filename (confirm via baseline diff)",
                    wf,
                ));
            }
        }
        for lit in &self.literals {
            if !Self::applies(&lit.applies_to, path) {
                continue;
            }
            if content.contains(lit.value.as_str()) {
                out.push(Finding::new(
                    path,
                    &lit.id,
                    &lit.severity,
                    &lit.category,
                    &lit.desc,
                    &snippet(content, &lit.value),
                ));
            }
        }
        for c in &self.combos {
            if c.all_of.iter().all(|s| content.contains(s.as_str())) {
                out.push(Finding::new(
                    path,
                    &c.id,
                    &c.severity,
                    &c.category,
                    &c.desc,
                    &c.all_of.join(" + "),
                ));
            }
        }
        for r in &self.regexes {
            if !Self::applies(&r.applies_to, path) {
                continue;
            }
            if let Some(req) = &r.requires {
                if !content.contains(req.as_str()) {
                    continue;
                }
            }
            if r.fallback && out.iter().any(|f| f.category == r.category) {
                continue;
            }
            if let Some(m) = r.re.find(content) {
                let ev = py::head(&squeeze_blanks(m.as_str()), 80).replace('\n', "\\n");
                out.push(Finding::new(
                    path,
                    &r.id,
                    &r.severity,
                    &r.category,
                    &r.desc,
                    &ev,
                ));
            }
        }
        for i in &self.iocs {
            if content.contains(i.value.as_str()) {
                out.push(Finding::new(
                    path,
                    &i.id,
                    &i.severity,
                    "network-ioc",
                    &i.desc,
                    &i.value,
                ));
            }
        }
        out
    }

    /// Added lines (+, not +++) of a unified diff, plus added workflow files.
    pub fn scan_diff(&self, diff: &str) -> Vec<Finding> {
        let lines = py::splitlines(diff);
        let added: Vec<&str> = lines
            .iter()
            .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
            .map(|l| &l[1..])
            .collect();
        let mut out = self.scan_content("diff", &added.join("\n"));
        for l in &lines {
            if l.starts_with("+++ b/.github/workflows/") {
                out.push(Finding::new(
                    "diff",
                    "wf.added",
                    "high",
                    "workflow",
                    "workflow file added by this diff",
                    &l[6..],
                ));
            }
        }
        out
    }
}

pub fn skip_path(prefixes: &[String], path: &str) -> bool {
    let norm = path.replace('\\', "/");
    // dependency code is never trusted: inside node_modules nothing is
    // skipped, not even a package's dist/ or build/
    let parts: Vec<&str> = norm.split('/').take_while(|c| *c != DEPS_DIR).collect();
    prefixes
        .iter()
        .any(|p| parts.contains(&p.trim_matches('/')))
}

/// Up to 40 characters either side of the first `needle`, newlines escaped.
/// Long runs of blanks (padding that pushes code off-screen) shown as a
/// count, so the evidence shows the code after them.
fn squeeze_blanks(s: &str) -> std::borrow::Cow<'_, str> {
    static BLANKS: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"[ \t]{20,}").unwrap());
    BLANKS.replace_all(s, |c: &regex::Captures| format!("[{} blanks]", c[0].len()))
}

fn snippet(text: &str, needle: &str) -> String {
    let Some(i) = text.find(needle) else {
        return String::new();
    };
    let start = text[..i].char_indices().rev().nth(39).map_or(0, |(j, _)| j);
    let after = i + needle.len();
    let end = text[after..]
        .char_indices()
        .nth(40)
        .map_or(text.len(), |(j, _)| after + j);
    text[start..end].replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippet_window() {
        let t = format!("{}NEEDLE{}", "a".repeat(50), "b".repeat(50));
        assert_eq!(
            snippet(&t, "NEEDLE"),
            format!("{}NEEDLE{}", "a".repeat(40), "b".repeat(40))
        );
        assert_eq!(snippet("x\nNEEDLEy", "NEEDLE"), "x\\nNEEDLEy");
        assert_eq!(snippet("é".repeat(45).as_str(), "é"), "é".repeat(41));
        assert_eq!(snippet("abc", "zz"), "");
    }

    fn ids(f: &[Finding]) -> Vec<&str> {
        let mut v: Vec<&str> = f.iter().map(|x| x.sig_id.as_str()).collect();
        v.sort_unstable();
        v
    }

    /// A `fallback` regex reports only when no rule of its category fired.
    #[test]
    fn fallback_regex() {
        let m = Matcher::new(&json!({
            "literals": [{"id": "lit", "severity": "critical", "category": "c",
                          "value": "known", "desc": "d"}],
            "regexes": [
                {"id": "gen", "severity": "critical", "category": "c",
                 "fallback": true, "pattern": "k\\w+", "desc": "d"},
                {"id": "other", "severity": "high", "category": "x",
                 "fallback": true, "pattern": "k\\w+", "desc": "d"}
            ]
        }))
        .unwrap();
        assert_eq!(ids(&m.scan_content("a.js", "kn0wn")), ["gen", "other"]);
        assert_eq!(ids(&m.scan_content("a.js", "known")), ["lit", "other"]);
    }

    /// test_legacy_engines.py TestFingerprintMatcher: names alone, pruned
    /// directories, diffs judged on added lines only.
    #[test]
    fn names_skips_and_diffs() {
        let m = Matcher::new(&super::super::sigs::load(None).unwrap()).unwrap();
        let eval = concat!("eval(proxy", "Info)");
        assert!(m.scan_content("a/dist/x/eval.js", eval).is_empty());
        // dependency code is scanned, dist/ inside it too
        assert!(!m.scan_content("a/node_modules/x/eval.js", eval).is_empty());
        assert!(!m
            .scan_content("a/node_modules/x/dist/eval.js", eval)
            .is_empty());
        assert!(m
            .scan_content("dist/node_modules/x/eval.js", eval)
            .is_empty());
        assert_eq!(
            ids(&m.scan_content("public/fonts/fa-solid-400.woff2", "")),
            ["drop.file.name"]
        );
        assert_eq!(
            ids(&m.scan_content(".github/workflows/ci.yml", "on: push")),
            ["wf.name"]
        );
        let atob = concat!("atob(process.env.", "AUTH_API_KEY)");
        let diff = format!(
            "diff --git a/x b/x\n+++ b/.github/workflows/evil.yml\n-{eval}\n+const a = 1;\n+{atob}\n"
        );
        let found = m.scan_diff(&diff);
        let got = ids(&found);
        assert!(
            got.contains(&"iife.marker.atob") && got.contains(&"wf.added"),
            "{got:?}"
        );
        assert!(!got.contains(&"iife.marker.eval"), "{got:?}");
    }
}
