//! Content heuristics — a line-for-line port of the data-dependent parts of
//! `guard_av/heuristics.py` (PE / ELF / Mach-O structure and script obfuscation).
//! Filename checks stay in Python. Every indicator id, score and description
//! must match the Python implementation exactly; the test suite runs both
//! backends and compares them.

use std::sync::LazyLock;

use memchr::memmem;
use regex::bytes::Regex;

use crate::entropy::shannon_entropy;

pub type Indicator = (&'static str, u32, String);

fn ind(id: &'static str, score: u32, desc: impl Into<String>) -> Indicator {
    (id, score, desc.into())
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    memmem::find(hay, needle).is_some()
}

// ---------------------------------------------------------------------- PE
const SCN_EXECUTE: u32 = 0x2000_0000;
const SCN_WRITE: u32 = 0x8000_0000;
const SCN_CODE: u32 = 0x0000_0020;

const PACKERS: &[(&[u8], &str)] = &[
    (b"UPX0", "UPX"), (b"UPX1", "UPX"), (b"UPX2", "UPX"),
    (b".aspack", "ASPack"), (b".adata", "ASPack"), (b".petite", "Petite"),
    (b".MPRESS1", "MPRESS"), (b".MPRESS2", "MPRESS"), (b".themida", "Themida"),
    (b".vmp0", "VMProtect"), (b".vmp1", "VMProtect"), (b".enigma1", "Enigma"),
    (b"nsp0", "NsPack"),
];

// API names are stored reversed: spelled out, they would sit in guard.exe
// itself, and a scan of the binary would flag it for process injection.
const API_GROUPS: &[(&str, u32, &str, &[&[u8]])] = &[
    ("pe.api.process-injection", 45, "classic remote-process injection API set",
     &[b"xEcollAlautriV", b"yromeMssecorPetirW", b"daerhTetomeRetaerC"]),
    ("pe.api.process-hollowing", 45, "process-hollowing API set",
     &[b"noitceSfOweiVpamnUtN", b"txetnoCdaerhTteS", b"daerhTemuseR"]),
    ("pe.api.keylogger", 30, "global keyboard hook + key-state polling",
     &[b"xEkooHswodniWteS", b"etatSyeKcnysAteG"]),
    ("pe.api.anti-debug", 10, "debugger-detection APIs",
     &[b"tneserPreggubeDsI", b"tneserPreggubeDetomeRkcehC"]),
];

struct Section {
    name: Vec<u8>,
    vaddr: u64,
    vsize: u64,
    raw_ptr: usize,
    raw_size: usize,
    flags: u32,
}

struct PeInfo {
    entry_point: u64,
    sections: Vec<Section>,
}

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o.checked_add(2)?).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o.checked_add(4)?).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Python slicing semantics: clamp instead of failing.
fn slice(d: &[u8], start: usize, len: usize) -> &[u8] {
    let s = start.min(d.len());
    let e = start.saturating_add(len).min(d.len());
    &d[s..e]
}

fn parse_pe(data: &[u8]) -> Option<PeInfo> {
    if !data.starts_with(b"MZ") {
        return None;
    }
    let e_lfanew = u32_at(data, 0x3C)? as usize;
    if slice(data, e_lfanew, 4) != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4;
    // struct "<HHIIIHH": machine, nsects, timestamp, symtab, nsyms, opt_size, chars
    u16_at(data, coff + 18)?; // the whole 20-byte header must be present
    let nsects = u16_at(data, coff + 2)? as usize;
    let opt_size = u16_at(data, coff + 16)? as usize;
    let opt = coff + 20;
    let magic = u16_at(data, opt)?;
    if magic != 0x10B && magic != 0x20B {
        return None;
    }
    let entry = u32_at(data, opt + 16)? as u64;
    let sec_off = opt + opt_size;
    let mut sections = Vec::new();
    for i in 0..nsects.min(96) {
        let o = sec_off + 40 * i;
        let mut name = slice(data, o, 8).to_vec();
        while name.last() == Some(&0) {
            name.pop();
        }
        // "<IIII" at o+8 then "<I" at o+36 (raising in Python if out of range)
        let vsize = u32_at(data, o + 8)? as u64;
        let vaddr = u32_at(data, o + 12)? as u64;
        let raw_size = u32_at(data, o + 16)? as usize;
        let raw_ptr = u32_at(data, o + 20)? as usize;
        let flags = u32_at(data, o + 36)?;
        sections.push(Section { name, vaddr, vsize, raw_ptr, raw_size, flags });
    }
    Some(PeInfo { entry_point: entry, sections })
}

/// Python `repr()` of a latin-1 decoded str (used in one description).
fn py_repr_latin1(b: &[u8]) -> String {
    let has_sq = b.contains(&b'\'');
    let has_dq = b.contains(&b'"');
    let quote = if has_sq && !has_dq { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for &c in b {
        match c {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            _ if c as char == quote => {
                out.push('\\');
                out.push(quote);
            }
            0x20..=0x7E => out.push(c as char),
            0xA1..=0xFF if c != 0xAD => out.push(c as char),
            _ => out.push_str(&format!("\\x{c:02x}")),
        }
    }
    out.push(quote);
    out
}

pub fn pe_indicators(data: &[u8]) -> Vec<Indicator> {
    let Some(info) = parse_pe(data) else {
        return vec![ind("pe.malformed", 15, "MZ header without a valid PE structure")];
    };
    let mut out = Vec::new();
    let mut packers: Vec<&str> = info
        .sections
        .iter()
        .filter_map(|s| PACKERS.iter().find(|(n, _)| *n == s.name.as_slice()).map(|(_, p)| *p))
        .collect();
    packers.sort_unstable();
    packers.dedup();
    if !packers.is_empty() {
        out.push(ind("pe.packer", 25, format!("packed with {}", packers.join(", "))));
    }
    for s in &info.sections {
        if s.flags & SCN_EXECUTE == 0 {
            continue;
        }
        let body = slice(data, s.raw_ptr, s.raw_size);
        if body.len() >= 1024 && shannon_entropy(body) > 7.2 {
            out.push(ind("pe.section.high-entropy", 35, format!(
                "executable section {} is encrypted/compressed", py_repr_latin1(&s.name))));
            break;
        }
    }
    if info.sections.iter().any(|s| s.flags & SCN_EXECUTE != 0 && s.flags & SCN_WRITE != 0) {
        out.push(ind("pe.section.wx", 20, "section is both writable and executable"));
    }
    if !info.sections.is_empty() && info.entry_point != 0 {
        let ep = info.entry_point;
        let inside = info
            .sections
            .iter()
            .find(|s| s.vaddr <= ep && ep < s.vaddr + s.vsize.max(s.raw_size as u64));
        match inside {
            None => out.push(ind("pe.entry.outside", 30, "entry point lies outside every section")),
            Some(s) if s.flags & (SCN_CODE | SCN_EXECUTE) == 0 => {
                out.push(ind("pe.entry.non-code", 30, "entry point is in a non-executable section"))
            }
            Some(_) => {}
        }
    }
    for (id, score, desc, apis) in API_GROUPS {
        if apis.iter().all(|a| contains(data, &a.iter().rev().copied().collect::<Vec<u8>>())) {
            out.push(ind(id, *score, *desc));
        }
    }
    out
}

// --------------------------------------------------------------- ELF / Mach-O
pub fn elf_indicators(data: &[u8]) -> Vec<Indicator> {
    let mut out = Vec::new();
    let head = &data[..data.len().min(4096)];
    let tail = &data[data.len().saturating_sub(4096)..];
    if contains(head, b"UPX!") || contains(tail, b"UPX!") {
        out.push(ind("elf.packer", 25, "packed with UPX"));
    }
    if data.len() >= 4096 && shannon_entropy(data) > 7.4 {
        out.push(ind("elf.high-entropy", 30, "body is encrypted/compressed"));
    }
    if contains(data, b"/etc/ld.so.preload") {
        out.push(ind("elf.ld-preload", 40, "writes the system-wide LD preload list (rootkit persistence)"));
    }
    out
}

pub fn macho_indicators(data: &[u8]) -> Vec<Indicator> {
    if data.len() >= 4096 && shannon_entropy(data) > 7.4 {
        return vec![ind("macho.high-entropy", 30, "body is encrypted/compressed")];
    }
    Vec::new()
}

// ------------------------------------------------------------------- scripts
fn re(src: &str) -> Regex {
    Regex::new(src).expect("built-in heuristic regex")
}

static DYNAMIC_EXEC: LazyLock<Regex> = LazyLock::new(|| re(
    r"(?-u)(?i)\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(|Invoke-Expression|\bIEX\b|\bexecute\s*\("));
static JSOBF_ID: LazyLock<Regex> = LazyLock::new(|| re(r"(?-u)\b_0x[0-9a-f]{4,6}\b"));
// bootstrap tag the _0x loader wave sets before its obfuscated body (issue #24)
static LOADER_MARKER: LazyLock<Regex> = LazyLock::new(|| re(
    r#"(?-u)\bglobal(?:\['!'\]|\["!"\]|\.i)\s*=\s*['"]A?\d{1,3}(?:-[0-9*]{1,6}){0,3}['"]"#));
// a base64 payload split into many short string literals (["Z2xv...","9iam..."].join(''))
static B64_CHUNK: LazyLock<Regex> = LazyLock::new(|| re(r#"(?-u)["'`][A-Za-z0-9+/]{32,}={0,2}["'`]"#));
static CHARCODE: LazyLock<Regex> = LazyLock::new(|| re(r"(?-u)fromCharCode\s*\(\s*(?:\d+\s*,\s*){29,}\d+"));
static HEX_ESC: LazyLock<Regex> = LazyLock::new(|| re(r"(?-u)\\x[0-9a-fA-F]{2}"));
static PS_ENC: LazyLock<Regex> = LazyLock::new(|| re(
    r"(?-u)(?i)-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/]{100}"));
static PS_HIDDEN: LazyLock<Regex> = LazyLock::new(|| re(r"(?-u)(?i)-(?:w|win|window|windowstyle)\s+hidden"));
static PS_FROMB64: LazyLock<Regex> = LazyLock::new(|| re(r"(?-u)(?i)FromBase64String"));
static PS_IEX: LazyLock<Regex> = LazyLock::new(|| re(r"(?-u)(?i)Invoke-Expression|\bIEX\b"));
static AMSI: LazyLock<Regex> = LazyLock::new(|| re(r"(?-u)(?i)Amsi(?:Utils|ScanBuffer)|amsi(?:Init)Failed"));

fn is_b64(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'+' || c == b'/'
}

/// Equivalent to Python's `re.search(rb"[A-Za-z0-9+/]{2000,}={0,2}", data)`.
fn has_b64_blob(data: &[u8]) -> bool {
    let mut run = 0usize;
    for &c in data {
        if is_b64(c) {
            run += 1;
            if run >= 2000 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// At least 2000 base64 characters spread over 10 or more quoted chunks, so
/// splitting the blob into short strings doesn't hide it from has_b64_blob.
fn has_b64_chunks(data: &[u8]) -> bool {
    let (mut n, mut total) = (0usize, 0usize);
    for m in B64_CHUNK.find_iter(data) {
        n += 1;
        total += m.len() - 2;
        if n >= 10 && total >= 2000 {
            return true;
        }
    }
    false
}

pub fn script_indicators(data: &[u8]) -> Vec<Indicator> {
    let mut out = Vec::new();
    let dyn_exec = DYNAMIC_EXEC.is_match(data);
    let exec_blob = dyn_exec && (has_b64_blob(data) || has_b64_chunks(data));
    if exec_blob {
        out.push(ind("script.exec-encoded-blob", 50, "dynamically executes code next to a large encoded blob"));
    }
    let marker = LOADER_MARKER.is_match(data);
    if JSOBF_ID.find_iter(data).count() >= 50 {
        out.push(ind("script.js-obfuscator", 35, "javascript-obfuscator style _0x identifiers"));
        if marker {
            out.push(ind("script.js-loader-marker", 40, "obfuscated loader tagged with a known campaign marker"));
        }
    } else if marker && exec_blob {
        // the same wave's lighter variant: marker, then an encoded body run by eval
        out.push(ind("script.js-loader-marker", 40, "executes code next to a known campaign marker"));
    }
    if dyn_exec && CHARCODE.is_match(data) {
        out.push(ind("script.charcode-exec", 40, "builds code from character codes and executes it"));
    }
    let n_hex = HEX_ESC.find_iter(data).count();
    if n_hex >= 300 && n_hex * 4 > data.len() / 3 {
        out.push(ind("script.hex-escaped", 25, "body is mostly hex-escaped bytes"));
    }
    if PS_ENC.is_match(data) {
        out.push(ind("ps.encoded-command", 30, "PowerShell launched with an encoded command"));
        if PS_HIDDEN.is_match(data) {
            out.push(ind("ps.hidden-window", 20, "PowerShell window hidden from the user"));
        }
    }
    if dyn_exec && PS_FROMB64.is_match(data) && PS_IEX.is_match(data) {
        out.push(ind("ps.decode-exec", 30, "decodes base64 and pipes it to Invoke-Expression"));
    }
    if AMSI.is_match(data) {
        out.push(ind("ps.amsi-bypass", 60, "tampers with the Antimalware Scan Interface"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(v: &[Indicator]) -> Vec<&str> {
        v.iter().map(|i| i.0).collect()
    }

    #[test]
    fn malformed_pe() {
        assert_eq!(ids(&pe_indicators(b"MZ")), ["pe.malformed"]);
        assert_eq!(ids(&pe_indicators(b"ELF")), ["pe.malformed"]);
    }

    #[test]
    fn repr_matches_python() {
        assert_eq!(py_repr_latin1(b"UPX0"), "'UPX0'");
        assert_eq!(py_repr_latin1(b"a'b"), "\"a'b\"");
        assert_eq!(py_repr_latin1(b"a'\"b"), "'a\\'\"b'");
        assert_eq!(py_repr_latin1(b"\x01\xad\xe9\\"), "'\\x01\\xad\u{e9}\\\\'");
    }

    #[test]
    fn scripts() {
        let blob = b"QUJD".repeat(600);
        let mut s = b"eval(atob('".to_vec();
        s.extend_from_slice(&blob);
        s.extend_from_slice(b"'))");
        assert_eq!(ids(&script_indicators(&s)), ["script.exec-encoded-blob"]);
        assert!(script_indicators(b"print('hi')").is_empty());
        // the same blob split into short literals and joined
        let mut s = b"var a=[".to_vec();
        for _ in 0..60 {
            s.extend_from_slice(b"\"");
            s.extend_from_slice(&b"QUJD".repeat(12));
            s.extend_from_slice(b"\",");
        }
        s.extend_from_slice(b"].join('');eval(atob(a));");
        assert_eq!(ids(&script_indicators(&s)), ["script.exec-encoded-blob"]);
        // short chunks, or too few of them, stay quiet
        assert!(script_indicators(b"eval(x);['QUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJD']").is_empty());
        // the campaign marker, split so this source never holds it
        let marker = [b"glo".as_slice(), b"bal.i = 'A1-*2';"].concat();
        let blob = format!("eval(atob('{}'))", "QUJD".repeat(600));
        let s = [marker.as_slice(), blob.as_bytes()].concat();
        assert_eq!(
            ids(&script_indicators(&s)),
            ["script.exec-encoded-blob", "script.js-loader-marker"]
        );
        // a file that only names the marker (a rule, an IR script) stays quiet
        let s = [marker.as_slice(), b"Invoke-Expression $x"].concat();
        assert!(script_indicators(&s).is_empty());
    }

    #[test]
    fn elf() {
        let mut d = b"\x7fELF".to_vec();
        d.extend_from_slice(&[0u8; 9000]);
        d.extend_from_slice(b"UPX!/etc/ld.so.preload");
        assert_eq!(ids(&elf_indicators(&d)), ["elf.packer", "elf.ld-preload"]);
        assert!(macho_indicators(b"\xcf\xfa\xed\xfe").is_empty());
    }

    // ---- test_av_heuristics.py, PE / ELF / Mach-O / scripts

    fn noise(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..n).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; (x >> 24) as u8 }).collect()
    }

    /// conftest.build_pe: a minimal PE32 image, sections at 0x1000, 0x2000, ...
    fn build_pe(sections: &[(&[u8], u32, Vec<u8>)], entry: u32, extra: &[u8], opt_magic: u16, dll: bool) -> Vec<u8> {
        let opt_size = 0xE0usize;
        let headers = 0x40 + 4 + 20 + opt_size + 40 * sections.len();
        let raw = (headers + 0x1FF) & !0x1FF;
        let mut out = vec![0u8; 0x40];
        out[0..2].copy_from_slice(b"MZ");
        out[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        out.extend_from_slice(b"PE\0\0");
        out.extend_from_slice(&0x14Cu16.to_le_bytes());
        out.extend_from_slice(&(sections.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0u8; 12]);
        out.extend_from_slice(&(opt_size as u16).to_le_bytes());
        out.extend_from_slice(&(if dll { 0x2000u16 } else { 0x0102 }).to_le_bytes());
        let mut opt = vec![0u8; opt_size];
        opt[0..2].copy_from_slice(&opt_magic.to_le_bytes());
        opt[16..20].copy_from_slice(&entry.to_le_bytes());
        out.extend_from_slice(&opt);
        let mut ptr = raw as u32;
        for (i, (name, flags, body)) in sections.iter().enumerate() {
            let mut n = [0u8; 8];
            n[..name.len()].copy_from_slice(name);
            out.extend_from_slice(&n);
            let len = body.len() as u32;
            for v in [len, 0x1000 * (i as u32 + 1), len, ptr, 0, 0] {
                out.extend_from_slice(&v.to_le_bytes());
            }
            out.extend_from_slice(&[0u8; 4]);
            out.extend_from_slice(&flags.to_le_bytes());
            ptr += len;
        }
        out.resize(raw, 0);
        for (_, _, body) in sections {
            out.extend_from_slice(body);
        }
        out.extend_from_slice(extra);
        out
    }

    const X: u32 = SCN_EXECUTE;
    const W: u32 = SCN_WRITE;
    const R: u32 = 0x4000_0000;
    const C: u32 = SCN_CODE;

    fn plain_pe(extra: &[u8]) -> Vec<u8> {
        build_pe(&[(b".text", X | R | C, vec![0x90; 512]), (b".data", R | W, vec![0; 512])], 0x1000, extra, 0x10B, false)
    }

    fn sorted(v: &[Indicator]) -> Vec<&str> {
        let mut ids = ids(v);
        ids.sort_unstable();
        ids
    }

    #[test]
    fn parse_pe_accepts_and_rejects() {
        let dll = build_pe(&[(b".text", X | R | C, vec![0x90; 512]), (b".data", R | W, vec![0; 512])], 0x1000, b"", 0x10B, true);
        let names: Vec<Vec<u8>> = parse_pe(&dll).unwrap().sections.into_iter().map(|s| s.name).collect();
        assert_eq!(names, [b".text".to_vec(), b".data".to_vec()]);
        assert!(parse_pe(&build_pe(&[], 0x1000, b"", 0x20B, false)).is_some());
        let mut no_pe = b"MZ".to_vec();
        no_pe.extend_from_slice(&[0u8; 0x3A]);
        no_pe.extend_from_slice(&0x40u32.to_le_bytes());
        no_pe.extend_from_slice(b"XX\0\0");
        for bad in [b"ELF".to_vec(), b"MZ".to_vec(), no_pe, build_pe(&[], 0x1000, b"", 0x999, false), plain_pe(b"")[..0x58].to_vec()] {
            assert!(parse_pe(&bad).is_none());
        }
    }

    #[test]
    fn pe_shapes() {
        assert!(pe_indicators(&plain_pe(b"")).is_empty());
        // anti-debug alone is common in legit software and stays tiny
        let lone = pe_indicators(&plain_pe(b"IsDebuggerPresent\0CheckRemoteDebuggerPresent\0"));
        assert_eq!(ids(&lone), ["pe.api.anti-debug"]);
        assert!(lone.iter().map(|i| i.1).sum::<u32>() < 70);
        assert_eq!(ids(&pe_indicators(&[b"MZ".as_slice(), &[0u8; 100]].concat())), ["pe.malformed"]);
        let apis: &[u8] = b"VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0NtUnmapViewOfSection\0SetThreadContext\0ResumeThread\0SetWindowsHookExA\0GetAsyncKeyState\0";
        let packed = build_pe(&[(b"UPX0", X | W | R, noise(4096, 7)), (b".rsrc", R, vec![0; 64])], 0x9000, apis, 0x10B, false);
        assert_eq!(sorted(&pe_indicators(&packed)), ["pe.api.keylogger", "pe.api.process-hollowing", "pe.api.process-injection",
                                                   "pe.entry.outside", "pe.packer", "pe.section.high-entropy", "pe.section.wx"]);
        let non_code = build_pe(&[(b".text", X | C | R, vec![0x90; 64]), (b".data", R | W, vec![0; 64])], 0x2000, b"", 0x10B, false);
        assert_eq!(ids(&pe_indicators(&non_code)), ["pe.entry.non-code"]);
        // a resource-only DLL has no entry point; no sections, nothing to judge
        let resource = build_pe(&[(b".text", X | R | C, vec![0x90; 512]), (b".data", R | W, vec![0; 512])], 0, b"", 0x10B, true);
        assert!(pe_indicators(&resource).is_empty());
        assert!(pe_indicators(&build_pe(&[], 0x1000, b"", 0x10B, false)).is_empty());
        // too small a section for its entropy to mean anything
        assert!(pe_indicators(&build_pe(&[(b".text", X | C, noise(512, 3))], 0x1000, b"", 0x10B, false)).is_empty());
    }

    #[test]
    fn elf_and_macho_shapes() {
        let elf = |body: &[u8]| [b"\x7fELF\x02\x01\x01".as_slice(), &[0u8; 9], body].concat();
        assert!(elf_indicators(&elf(&[0u8; 64])).is_empty());
        let packed = elf(&[b"UPX!".as_slice(), &noise(8192, 5), b"/etc/ld.so.preload"].concat());
        assert_eq!(ids(&elf_indicators(&packed)), ["elf.packer", "elf.high-entropy", "elf.ld-preload"]);
        assert_eq!(ids(&elf_indicators(&elf(&[vec![0u8; 9000], b"UPX!".to_vec()].concat()))), ["elf.packer"]);
        assert!(macho_indicators(&[b"\xcf\xfa\xed\xfe".as_slice(), &[0u8; 5000]].concat()).is_empty());
        let random = [b"\xcf\xfa\xed\xfe".as_slice(), &noise(5000, 9)].concat();
        assert_eq!(ids(&macho_indicators(&random)), ["macho.high-entropy"]);
    }

    #[test]
    fn script_cases() {
        let blob = "QUJD".repeat(600);
        let x_ids = |n: usize| (0..n).map(|i| format!("_0x{i:04x}")).collect::<Vec<_>>().join(" ");
        let codes = |same: bool| (0..40).map(|i| if same { 65 } else { 65 + i % 26 }.to_string()).collect::<Vec<_>>().join(",");
        let a = "A".repeat(120);
        // split so this source never holds the strings the rules hunt for
        let iex = ["I", "EX"].concat();
        let amsi = ["Amsi", "ScanBuffer"].concat();
        let bang = ["glo", "bal['!']="].concat();
        let gi = ["glo", "bal.i="].concat();
        let cases: Vec<(String, Vec<&str>)> = vec![
            (format!("eval(atob('{blob}'))"), vec!["script.exec-encoded-blob"]),
            (format!("const img = 'data:image/png;base64,{blob}';"), vec![]),
            (x_ids(60), vec!["script.js-obfuscator"]),
            (x_ids(10), vec![]),
            (format!("{}{}", [bang.as_str(), "'9-6600';"].concat(), x_ids(60)), vec!["script.js-obfuscator", "script.js-loader-marker"]),
            (format!("{}{}", [gi.as_str(), "\"A10-1300\";"].concat(), x_ids(60)), vec!["script.js-obfuscator", "script.js-loader-marker"]),
            (format!("{}{}", [bang.as_str(), "'9-6600';"].concat(), x_ids(10)), vec![]),
            (format!("{}{}", [bang.as_str(), "fn;"].concat(), x_ids(60)), vec!["script.js-obfuscator"]),
            (format!("eval(String.fromCharCode({}))", codes(false)), vec!["script.charcode-exec"]),
            (format!("String.fromCharCode({})", codes(true)), vec![]),
            ("\\x41".repeat(400), vec!["script.hex-escaped"]),
            (format!("{}{}", "\\x41".repeat(400), "A".repeat(10000)), vec![]),
            (format!("powershell -enc {a}"), vec!["ps.encoded-command"]),
            (format!("powershell -w hidden -EncodedCommand {a}"), vec!["ps.encoded-command", "ps.hidden-window"]),
            ("powershell -w hidden -c Get-Date".into(), vec![]),
            (format!("{iex} ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)))"), vec!["ps.decode-exec"]),
            ("[Convert]::FromBase64String($p)".into(), vec![]),
            (format!("x = 'Amsi' + 'ScanBuffer'; {amsi}"), vec!["ps.amsi-bypass"]),
            ("print('hello world')".into(), vec![]),
        ];
        for (data, want) in cases {
            let got = script_indicators(data.as_bytes());
            let mut want = want;
            want.sort_unstable();
            assert_eq!(sorted(&got), want, "{}", &data[..data.len().min(60)]);
        }
    }
}

