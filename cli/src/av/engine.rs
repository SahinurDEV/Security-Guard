//! The scan pipeline (port of guard_av/engine.py).
//!
//! Per object (a file, or a member unpacked from an archive): hash and identify
//! by content; allowlist; hash DB; JSON + YARA rules; heuristics; recurse into
//! archives. Results are cached by (sha256, filename). Read-only.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::allowlist::Allowlist;
use super::archive::{self, Limits};
use super::filetype as ft;
use super::hashdb::HashDatabase;
use super::hashing::{self, Hashes};
use super::heuristics::{self, STRONG};
use super::model::{Detection, ScanResult, Verdict};
use super::pystr;
use super::rules::RuleSet;
use super::yara::{self, YaraRuleSet};

// gzipped by build.rs: plain signature text in the binary would match the rules
static BUNDLED_RULES_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/av-rules.json.gz"));
static BUNDLED_HASHES_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/av-hashes.json.gz"));
// BUNDLED_YARA: the community YARA rule sets in data/yara, one namespace each
include!(concat!(env!("OUT_DIR"), "/bundled_yara.rs"));
pub static YARA_LICENSES_GZ: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/yara-licenses.txt.gz"));

/// GUARD_COMMUNITY_RULES=0 leaves the bundled community YARA rules out (they
/// add a few seconds of rule compilation to every engine start).
pub fn community_rules_enabled() -> bool {
    !matches!(
        std::env::var("GUARD_COMMUNITY_RULES")
            .as_deref()
            .map(str::trim),
        Ok("0" | "off" | "false" | "no")
    )
}

pub fn gunzip(gz: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_end(&mut out)
        .expect("bundled signatures decompress");
    out
}

/// Content examined per file; hashes always cover the whole file.
pub const MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ARCHIVE_DEPTH: usize = 3;
const SUSPICIOUS_THRESHOLD: u32 = 70;
const MALICIOUS_THRESHOLD: u32 = 150;
const MALICIOUS_MIN_STRONG: usize = 3;
const SKIP_DIRS: &[&str] = &[".git", ".hg", ".svn"];
const CACHE_SIZE: usize = 4096;

pub struct Config {
    pub scan_archives: bool,
    pub heuristics: bool,
    pub max_scan_bytes: u64,
    /// load the bundled community YARA rules (see community_rules_enabled)
    pub community_rules: bool,
}

#[derive(Default)]
pub struct Summary {
    pub scanned: u64,
    pub malicious: u64,
    pub suspicious: u64,
    pub errors: u64,
    pub elapsed: f64,
    pub results: Vec<ScanResult>,
}

/// "quarantine" for anything malicious or suspicious (no manual review),
/// "" when there is nothing to do.
pub fn action_hint(r: &ScanResult) -> &'static str {
    if r.verdict == Verdict::Clean {
        ""
    } else {
        "quarantine"
    }
}

/// LRU of results by (sha256, filename).
#[derive(Default)]
struct Cache {
    tick: u64,
    map: HashMap<(String, String), (u64, ScanResult)>,
    order: BTreeMap<u64, (String, String)>,
}

impl Cache {
    fn get(&mut self, key: &(String, String)) -> Option<ScanResult> {
        self.tick += 1;
        let (t, r) = self.map.get_mut(key)?;
        self.order.remove(t);
        *t = self.tick;
        self.order.insert(self.tick, key.clone());
        Some(r.clone())
    }

    fn put(&mut self, key: (String, String), r: ScanResult) {
        self.tick += 1;
        self.order.insert(self.tick, key.clone());
        if let Some((old, _)) = self.map.insert(key, (self.tick, r)) {
            self.order.remove(&old);
        }
        if self.map.len() > CACHE_SIZE {
            if let Some((_, k)) = self.order.pop_first() {
                self.map.remove(&k);
            }
        }
    }
}

pub struct Engine {
    pub config: Config,
    pub rules: RuleSet,
    pub yara: YaraRuleSet,
    pub hashdb: HashDatabase,
    allowlist: Allowlist,
    limits: Limits,
    cache: Cache,
}

/// Files in `d` whose name matches prefix*suffix (pathlib glob), sorted.
fn glob(d: &Path, prefix: &str, suffix: &str) -> Vec<PathBuf> {
    let fold = |s: &str| {
        if cfg!(windows) {
            s.to_lowercase()
        } else {
            s.to_string()
        }
    };
    let mut out: Vec<(String, PathBuf)> = fs::read_dir(d)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            let f = fold(&n);
            (f.starts_with(prefix) && f.len() >= prefix.len() + suffix.len() && f.ends_with(suffix))
                .then(|| (f, e.path()))
        })
        .filter(|(_, p)| p.is_file())
        .collect();
    out.sort();
    out.into_iter().map(|(_, p)| p).collect()
}

fn read(p: &Path) -> Result<Vec<u8>, String> {
    fs::read(p).map_err(|e| pystr::os_error(&e, &p.display().to_string()))
}

fn text(p: &Path, bytes: &[u8]) -> Result<String, String> {
    String::from_utf8(bytes.to_vec()).map_err(|e| format!("{}: {e}", p.display()))
}

impl Engine {
    /// Bundled signatures plus any user rules / hashes / allowlists. Every
    /// signature file is allowlisted by hash: Guard never flags its own
    /// definitions.
    pub fn new(config: Config, extra_dirs: &[PathBuf]) -> Result<Engine, String> {
        let mut e = Engine {
            config,
            rules: RuleSet::default(),
            yara: YaraRuleSet::default(),
            hashdb: HashDatabase::default(),
            allowlist: Allowlist::default(),
            limits: Limits::default(),
            cache: Cache::default(),
        };
        let (rules, hashes) = (gunzip(BUNDLED_RULES_GZ), gunzip(BUNDLED_HASHES_GZ));
        e.rules
            .load_text(&String::from_utf8_lossy(&rules))
            .map_err(|m| format!("<bundled>/rules.json: {m}"))?;
        e.allowlist.add_hash(&hashing::hash_bytes(&rules).sha256);
        e.hashdb.load(Path::new("hashes.json"), &hashes)?;
        e.allowlist.add_hash(&hashing::hash_bytes(&hashes).sha256);
        if e.config.community_rules {
            for (namespace, gz) in BUNDLED_YARA {
                let src = gunzip(gz);
                e.yara.load(&format!("<bundled>/{namespace}.yar"), &src);
                e.allowlist.add_hash(&hashing::hash_bytes(&src).sha256);
            }
        }
        for d in extra_dirs {
            e.load_dir(d)?;
        }
        e.rules.compile()?;
        e.yara.compile()?; // once, after every file: fail here, naming the file, not mid-scan
        Ok(e)
    }

    fn load_dir(&mut self, d: &Path) -> Result<(), String> {
        for f in glob(d, "rules", ".json") {
            let b = read(&f)?;
            self.rules
                .load_text(&text(&f, &b)?)
                .map_err(|m| format!("{}: {m}", f.display()))?;
            self.allowlist.add_hash(&hashing::hash_bytes(&b).sha256);
        }
        let mut yara_files: Vec<(String, PathBuf)> = fs::read_dir(d)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                let s = pystr::suffix(&p.to_string_lossy()).to_lowercase();
                yara::SUFFIXES.contains(&s.as_str()) && p.is_file()
            })
            .map(|p| {
                let n = p
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                (if cfg!(windows) { n.to_lowercase() } else { n }, p)
            })
            .collect();
        yara_files.sort();
        for (_, f) in &yara_files {
            let b = read(f)?;
            self.yara
                .load(&crate::deps::py_path_str(&f.to_string_lossy()), &b);
            self.allowlist.add_hash(&hashing::hash_bytes(&b).sha256);
        }
        let mut hash_files = glob(d, "hashes", ".json");
        hash_files.extend(glob(d, "hashes", ".txt"));
        for f in hash_files {
            let b = read(&f)?;
            self.hashdb
                .load(&f, &b)
                .map_err(|m| format!("{}: {m}", f.display()))?;
            self.allowlist.add_hash(&hashing::hash_bytes(&b).sha256);
        }
        for f in glob(d, "allowlist", ".json") {
            let b = read(&f)?;
            let a = Allowlist::load(&text(&f, &b)?).map_err(|m| format!("{}: {m}", f.display()))?;
            self.allowlist.merge(a);
        }
        Ok(())
    }

    pub fn scan_bytes(
        &mut self,
        data: &[u8],
        name: &str,
        hashes: Option<Hashes>,
        size: Option<u64>,
        depth: usize,
    ) -> ScanResult {
        let hashes = hashes.unwrap_or_else(|| hashing::hash_bytes(data));
        let size = size.unwrap_or(data.len() as u64);
        let tag = ft::identify(&data[..data.len().min(4096)], name);
        let mut res = ScanResult::new(name.to_string());
        res.size = size;
        res.filetype = tag.to_string();
        res.md5 = hashes.md5.clone();
        res.sha1 = hashes.sha1.clone();
        res.sha256 = hashes.sha256.clone();

        let reason = self.allowlist.file_reason(name, &hashes.sha256);
        if !reason.is_empty() {
            res.allowlisted = reason;
            return res;
        }

        let last = name.rsplit('!').next().unwrap_or(name);
        let key = (hashes.sha256.clone(), pystr::name(last).to_string());
        if let Some(mut cached) = self.cache.get(&key) {
            cached.path = name.to_string();
            return cached;
        }

        if let Some((algo, entry)) = self.hashdb.lookup(&hashes) {
            res.detections.push(Detection {
                engine: "hash",
                name: entry.name.clone(),
                verdict: entry.verdict,
                whole_file: true,
                description: format!("{algo} matches a known-malware signature"),
                evidence: format!("{algo}:{}", hashes.get(algo)),
                ..Default::default()
            });
        }

        let mut dets = self.rules.scan(data, name, tag, size);
        dets.extend(self.yara.scan(data));
        for d in dets {
            if !self.allowlist.suppresses(&d) {
                res.detections.push(d);
            }
        }

        if self.config.heuristics {
            self.heuristics(&mut res, data, name, tag);
        }
        if self.config.scan_archives && ft::is_archive(tag) && depth < MAX_ARCHIVE_DEPTH {
            self.scan_archive(&mut res, data, name, tag, depth);
        }
        res.finalize();
        self.cache.put(key, res.clone());
        res
    }

    fn heuristics(&self, res: &mut ScanResult, data: &[u8], name: &str, tag: &str) {
        let ind = heuristics::analyze(data, name, tag);
        res.heuristic_score = ind.iter().map(|i| i.score).sum();
        if res.heuristic_score < SUSPICIOUS_THRESHOLD {
            return;
        }
        let strong = ind.iter().filter(|i| i.score >= STRONG).count();
        let malicious =
            res.heuristic_score >= MALICIOUS_THRESHOLD && strong >= MALICIOUS_MIN_STRONG;
        let mut top = &ind[0];
        for i in &ind[1..] {
            if i.score > top.score {
                top = i;
            }
        }
        let d = Detection {
            engine: "heuristic",
            name: format!(
                "Heur.{}.{}",
                if malicious { "Malware" } else { "Suspicious" },
                top.id
            ),
            verdict: if malicious {
                Verdict::Malicious
            } else {
                Verdict::Suspicious
            },
            description: ind
                .iter()
                .map(|i| i.description.as_str())
                .collect::<Vec<_>>()
                .join("; "),
            evidence: ind
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            score: res.heuristic_score,
            whole_file: ft::is_executable(tag),
            ..Default::default()
        };
        if !self.allowlist.suppresses(&d) {
            res.detections.push(d);
        }
    }

    fn scan_archive(
        &mut self,
        res: &mut ScanResult,
        data: &[u8],
        name: &str,
        tag: &str,
        depth: usize,
    ) {
        let ex = archive::extract(data, tag, name, &self.limits);
        if ex.bomb {
            let d = Detection {
                engine: "archive",
                name: "Archive.Bomb".into(),
                verdict: Verdict::Suspicious,
                description: "decompression bomb (extreme compression ratio)".into(),
                evidence: ex.notes.join("; "),
                whole_file: true,
                ..Default::default()
            };
            if !self.allowlist.suppresses(&d) {
                res.detections.push(d);
            }
        }
        for m in ex.members {
            let child = self.scan_bytes(
                &m.data,
                &format!("{name}!{}", m.name),
                None,
                None,
                depth + 1,
            );
            if child.verdict != Verdict::Clean {
                res.children.push(child);
            }
        }
    }

    pub fn scan_file(&mut self, p: &Path) -> ScanResult {
        let shown = crate::deps::py_path_str(&p.to_string_lossy());
        let read = || -> std::io::Result<(Vec<u8>, u64, Hashes)> {
            let size = fs::metadata(p)?.len();
            let mut data = Vec::new();
            fs::File::open(p)?
                .take(self.config.max_scan_bytes)
                .read_to_end(&mut data)?;
            let hashes = if size <= data.len() as u64 {
                hashing::hash_bytes(&data)
            } else {
                hashing::hash_file(p)?
            };
            Ok((data, size, hashes))
        };
        match read() {
            Ok((data, size, hashes)) => self.scan_bytes(&data, &shown, Some(hashes), Some(size), 0),
            Err(e) => {
                let mut r = ScanResult::new(shown.clone());
                r.error = format!(
                    "{}: {}",
                    pystr::os_error_class(&e),
                    pystr::os_error(&e, &shown)
                );
                r
            }
        }
    }

    /// Regular files under `target` in os.walk order: sorted, depth first,
    /// never following symlinks out of the tree, skipping VCS directories.
    pub fn iter_files(target: &str) -> Vec<PathBuf> {
        let t = PathBuf::from(crate::deps::py_path_str(target));
        if t.is_file() {
            return vec![t];
        }
        let mut out = Vec::new();
        walk(&t, &mut out);
        out
    }

    pub fn scan_path(&mut self, target: &str, on_result: &mut dyn FnMut(&ScanResult)) -> Summary {
        let start = Instant::now();
        let mut s = Summary::default();
        for p in Engine::iter_files(target) {
            let r = self.scan_file(&p);
            s.scanned += 1;
            if !r.error.is_empty() {
                s.errors += 1;
            } else if r.verdict == Verdict::Malicious {
                s.malicious += 1;
            } else if r.verdict == Verdict::Suspicious {
                s.suspicious += 1;
            }
            on_result(&r);
            if !r.error.is_empty() || r.verdict != Verdict::Clean {
                s.results.push(r);
            }
        }
        s.elapsed = start.elapsed().as_secs_f64();
        s
    }
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let (mut dirs, mut files) = (Vec::new(), Vec::new());
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let p = e.path();
        if p.is_dir() {
            dirs.push((name, p));
        } else {
            files.push((name, p));
        }
    }
    files.sort();
    dirs.sort();
    for (_, p) in files {
        let link = fs::symlink_metadata(&p)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(true);
        if !link && p.is_file() {
            out.push(p);
        }
    }
    for (name, p) in dirs {
        if SKIP_DIRS.contains(&name.as_str()) {
            continue;
        }
        let link = fs::symlink_metadata(&p)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(true);
        if !link {
            walk(&p, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(max_scan_bytes: u64) -> Engine {
        let cfg = Config {
            scan_archives: true,
            heuristics: true,
            max_scan_bytes,
            community_rules: false, // these tests are about the engine, not the rules
        };
        Engine::new(cfg, &[]).unwrap()
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("guard-engine-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn eicar() -> Vec<u8> {
        // the EICAR test string, reversed so this source never holds it
        let rev = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X";
        rev.chars().rev().collect::<String>().into_bytes()
    }

    /// test_av_engine.py test_large_file_hashes_whole_file_but_scans_prefix:
    /// only max_scan_bytes are examined, the hashes cover the whole file.
    #[test]
    fn large_file_hashes_whole_file_but_scans_prefix() {
        let d = tmp("big");
        let data = [eicar(), b"\n".to_vec(), vec![b'A'; 5000]].concat();
        let f = d.join("big.bin");
        fs::write(&f, &data).unwrap();
        let mut e = engine(1024);
        let r = e.scan_file(&f);
        assert_eq!(r.size, data.len() as u64);
        assert_eq!(r.sha256, hashing::hash_bytes(&data).sha256);
        let mut e = engine(1024);
        e.hashdb
            .add(&hashing::hash_bytes(&data).sha256, "Big.Bad", "malicious")
            .unwrap();
        assert_eq!(e.scan_file(&f).threat_name(), "Big.Bad");
        let r = e.scan_file(&d.join("missing"));
        assert!(r.error.starts_with("FileNotFoundError"), "{}", r.error);
        fs::remove_dir_all(&d).unwrap();
    }

    /// The fake-font loader Bipul downloaded (fa-solid-700.otf): blank
    /// padding, the campaign marker, a base64 body split into short strings,
    /// eval. Rebuilt here with a harmless body; the marker is split so this
    /// source never holds it.
    #[test]
    fn fake_font_loader_is_malicious() {
        let chunk = "Y29uc29sZS5sb2coMSk7Y29uc29sZS5sb2coMSk7Y29uc29s";
        let body: Vec<String> = (0..60).map(|_| format!("\"{chunk}\"")).collect();
        let src = format!(
            "{}{}{}(function(p){{var a=[{}];eval(atob(a.join('')));}})();",
            " ".repeat(500),
            "glo",
            "bal.i = 'A10-*090';",
            body.join(",")
        );
        let d = tmp("font");
        let f = d.join("fa-solid-700.otf");
        fs::write(&f, &src).unwrap();
        let r = engine(MAX_SCAN_BYTES).scan_file(&f);
        assert_eq!(r.verdict, Verdict::Malicious, "{:?}", r.detections);
        assert_eq!(action_hint(&r), "quarantine");
        fs::remove_dir_all(&d).unwrap();
    }

    /// test_archive_limits_configurable: members past the limit are not seen.
    #[test]
    fn archive_limits_apply() {
        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (n, data) in [("a.txt", b"fine".to_vec()), ("e.com", eicar())] {
            zw.start_file(n, zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut zw, &data).unwrap();
        }
        let z = zw.finish().unwrap().into_inner();
        let mut e = engine(MAX_SCAN_BYTES);
        assert_eq!(
            e.scan_bytes(&z, "z.zip", None, None, 0).verdict,
            Verdict::Malicious
        );
        let mut e = engine(MAX_SCAN_BYTES);
        e.limits.max_members = 1;
        assert_eq!(
            e.scan_bytes(&z, "z.zip", None, None, 0).verdict,
            Verdict::Clean
        );
    }

    /// test_lru_eviction_and_disabled: the cache keeps the most recently used.
    #[test]
    fn cache_is_lru() {
        let mut c = Cache::default();
        let key = |i: usize| (format!("{i}"), "f".to_string());
        for i in 0..=CACHE_SIZE {
            c.put(key(i), ScanResult::new(format!("p{i}")));
            if i == 1 {
                assert!(c.get(&key(0)).is_some()); // 0 is now newer than 1
            }
        }
        assert_eq!(c.map.len(), CACHE_SIZE);
        assert!(c.get(&key(1)).is_none());
        assert!(c.get(&key(0)).is_some());
    }

    /// test_bundled_rules_are_valid_and_unique.
    #[test]
    fn bundled_rules_are_described() {
        let e = engine(MAX_SCAN_BYTES);
        assert!(e.rules.len() >= 15);
        for r in &e.rules.rules {
            assert!(!r.description.is_empty(), "{}", r.id);
            assert!(matches!(
                r.verdict,
                Verdict::Malicious | Verdict::Suspicious
            ));
        }
        assert!(e.hashdb.len() > 0);
    }
}
