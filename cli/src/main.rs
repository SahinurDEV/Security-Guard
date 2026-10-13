//! guard — the single Guard entrypoint, as one static Rust binary.
//!
//! This is what releases ship (guard-<os>-<arch>), in place of the PyInstaller
//! build of guard.py it replaced. The integration tests in cli/tests compare it
//! with output recorded from that Python build.

mod av;
mod deps;
mod hooks;
mod install;
mod net;
mod notify;
mod permissions;
mod pyjson;
mod pyrepr;
mod scan;
mod sensor;
mod update;
mod util;
mod watch;

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

/// Release builds bake the version in with GUARD_VERSION at compile time.
pub const VERSION: &str = match option_env!("GUARD_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

// gzipped by build.rs: both name the incident's IOCs, which in plain text would
// make `guard scan` flag the binary itself
static TRIAGE_SH_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/guard-triage-linux.sh.gz"));
static SYSMON_CONFIG_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sysmon-config.xml.gz"));

const USAGE: &str = "\
guard - supply-chain and malware protection, one command: `guard <cmd>`.

Commands in this build:
  guard scan <path>        full repo/tree scan (fingerprints, droppers, vscode, workflows, malware deps)
  guard scan-git <path>    scan working tree AND every added line across git history
  guard scan-push          pre-push gate: scan what a push sends, block it on malware (git hook)
  guard open <path>        pre-open check: safe to open this folder in VS Code?
  guard clean <path>       REMOVE injected malware: excise bad code, keep the real file (backs up first)
  guard restore <path>     undo a clean/quarantine from the backup store
  guard triage             host IR triage (reboots/persistence/recon/flood) - OS-native
  guard permissions        check disk access; on macOS raise the \"Allow\" prompts (internal + removable)
  guard notify-test        show a sample threat popup (verify desktop alerts work)
  guard deps update        refresh the malware-package blocklist from GitHub advisories
  guard deps check <path>  check a project's dependencies against the malware blocklist [--blocklist FILE]
  guard hooks install      global git hooks for every repo (clone/pull scan + pre-push gate); also uninstall|status
  guard install            install Guard as an auto-start service on this machine
  guard uninstall          remove the Guard service + hooks
  guard update             check the signed update channel now (blocklist + binary)
  guard version            print version

  guard av scan <path>     antivirus engine: hash DB + YARA-style rules + heuristics + archives
  guard av quarantine ...  list / restore / delete items in the neutered quarantine vault
  guard watch              start the always-on filesystem watcher (the service runs this)
  guard sensor             Windows sensor: Sysmon + reboot events -> alerts (--selftest runs anywhere)
";

fn report(r: Result<u8, String>) -> u8 {
    r.unwrap_or_else(|e| {
        eprintln!("guard: {e}");
        1
    })
}

/// Run the bundled triage script (Linux/macOS) the way guard.py does.
fn triage(args: &[String]) -> u8 {
    if cfg!(windows) {
        println!(
            "On Windows, host triage uses the Sysmon-based sensor (`guard sensor`) + IR scripts."
        );
        println!("Run:  guard-triage.ps1 / reboot-forensics.ps1 (bundled under windows/),");
        println!("and install Sysmon with windows/sysmon-config.xml. See windows/README-windows-sensor.md.");
        return 0;
    }
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        eprintln!("unsupported platform for triage: {}", std::env::consts::OS);
        return 2;
    }
    // copy out so it's executable from anywhere
    let dir = std::env::temp_dir().join(format!("guard_{}", std::process::id()));
    let script: PathBuf = dir.join("triage.sh");
    let written = std::fs::create_dir_all(&dir)
        .and_then(|_| std::fs::write(&script, scan::gunzip(TRIAGE_SH_GZ)));
    if let Err(e) = written {
        eprintln!("could not stage the triage script: {e}");
        return 1;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755));
    }
    let rc = Command::new("bash").arg(&script).args(args).status();
    let _ = std::fs::remove_dir_all(&dir);
    match rc {
        Ok(s) => s.code().unwrap_or(1) as u8,
        Err(e) => {
            eprintln!("bash: {e}");
            1
        }
    }
}

/// Emit the bundled Sysmon config (guard.ps1 configures Sysmon from it).
fn sysmon_config(args: &[String]) -> u8 {
    match args.first() {
        Some(dest) => match std::fs::write(dest, scan::gunzip(SYSMON_CONFIG_GZ)) {
            Ok(()) => {
                println!("wrote {dest}");
                0
            }
            Err(e) => {
                eprintln!("could not write {dest}: {e}");
                1
            }
        },
        None => {
            let mut out = std::io::stdout().lock();
            let _ = out
                .write_all(&scan::gunzip(SYSMON_CONFIG_GZ))
                .and_then(|_| out.flush());
            0
        }
    }
}

fn run(args: &[String]) -> u8 {
    update::cleanup_stale();
    let Some(cmd) = args.first() else {
        print!("{USAGE}");
        return 0;
    };
    let rest = &args[1..];
    match cmd.as_str() {
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            0
        }
        "version" => {
            println!("guard {VERSION}");
            0
        }
        "triage" => triage(rest),
        "permissions" | "perms" => permissions::main(rest),
        "sysmon-config" => sysmon_config(rest),
        "notify-test" => {
            let ok = notify::notify(
                "Guard - Threat detected (TEST)",
                "This is a TEST alert. If you can see this, Guard's threat notifications work on this machine.",
            );
            println!(
                "{}",
                if ok {
                    "notified"
                } else {
                    "notify returned False (no mechanism available)"
                }
            );
            if ok {
                0
            } else {
                1
            }
        }
        "av" => av::main(rest),
        "scan" => scan::main("scan-tree", rest),
        "scan-git" => scan::main("scan-git", rest),
        "scan-push" => scan::push::main(rest),
        "open" => scan::main("guard-open", rest),
        "clean" | "restore" => scan::remediate_main(cmd, rest),
        "deps" => report(deps::main(rest)),
        // manual OTA check (the service also does this periodically)
        "update" => match update::Updater::from_env(VERSION).and_then(|up| up.check_and_apply()) {
            Ok(res) => {
                println!("{}", res.repr());
                0
            }
            Err(e) => {
                eprintln!("update failed: {e}");
                1
            }
        },
        "watch" => watch::main(rest),
        "sensor" => sensor::main(rest),
        "hooks" => hooks::main(rest),
        "install" => report(install::run(false)),
        "uninstall" => report(install::run(true)),
        c => {
            eprintln!("unknown command: {c}\n");
            eprint!("{USAGE}");
            2
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(run(&args))
}
