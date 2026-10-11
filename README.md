# Guard — antivirus & supply-chain malware agent

[![tests](https://github.com/Syed-Bipul-Rahman/Security-Guard/actions/workflows/tests.yml/badge.svg)](https://github.com/Syed-Bipul-Rahman/Security-Guard/actions/workflows/tests.yml)
![false positives](https://img.shields.io/badge/false%20positives-0-brightgreen)
![version](https://img.shields.io/badge/version-2.0.0-blue)

One self-contained `guard` binary for every user machine (**Linux / macOS /
Windows**). It runs always-on and combines two engines:

- a **general antivirus engine** (`guard av`) — hash signatures, YARA-style
  rules, static heuristics and recursive archive scanning for webshells, reverse
  shells, credential dumpers, droppers, malicious macros, packed injectors,
  miners and more;
- **supply-chain malware detection** for the fake-font dropper / `.vscode`
  auto-run / obfuscated `eval` C2 family, including payloads hidden in git history.

It **auto-removes** what it finds — excising injected code while keeping your
real files, or moving whole-file malware into a neutered quarantine — and **warns
the user** with a desktop notification, like a consumer antivirus. It
self-updates over the air and sends no telemetry.

- **Repo:** https://github.com/Syed-Bipul-Rahman/Security-Guard
- **Releases:** https://github.com/Syed-Bipul-Rahman/Security-Guard/releases
- **Install site:** https://security.sparktech.agency

---

## What's new in v2.0.0

- **New antivirus engine (`guard av`)** — layered hash DB → YARA-style rules →
  heuristics → archive scanning, used automatically by the watcher, `guard scan`
  and `guard clean`, and directly via `guard av ...`. See
  [Antivirus engine](#antivirus-engine-guard-av).
- **Neutered quarantine vault** — whole-file threats are stored encrypted with a
  per-item key and restored only after a SHA-256 integrity check.
- **422 tests, 100% line + branch coverage** of the detection and remediation
  stack, plus a **zero-false-positive** gate (Python stdlib, system binaries,
  an adversarial benign corpus and this repo). CI runs on every push; releases
  are only built when it passes.
- **Fixes:** malformed `.vscode/settings.json` / `tasks.json` no longer slip past
  the pre-open check (it now fails closed as intended), and OTA signature
  verification rejects non-canonical Ed25519 signatures (RFC 8032).

---

## Install (one command)

**macOS / Linux** (installs the always-on service, auto-starts on boot):
```bash
curl -fsSL https://security.sparktech.agency/guard.sh | sudo bash
```

**Windows** (run in an **elevated** PowerShell):
```powershell
irm https://security.sparktech.agency/guard.ps1 | iex
```

The installer downloads the right binary for your OS/arch, verifies its SHA-256,
installs it, registers the auto-start watcher service, trusts Guard in Microsoft
Defender, and (Windows) auto-configures Sysmon. Supported targets: `linux-x64`,
`linux-arm64`, `darwin-arm64`, `windows-x64`, `windows-arm64`.

Uninstall anytime: `sudo guard uninstall` (or `guard uninstall` on Windows).

---

## Features

- **Antivirus engine** — exact hash signatures, 15 high-confidence YARA-style
  rules, about 2,300 community YARA rules (ReversingLabs, Neo23x0
  signature-base, ESET, Google GCTI, Airbnb BinaryAlert; see
  [data/yara](data/yara/README.md)), static heuristics (packers, injection APIs, obfuscation, disguised
  filenames) and bomb-safe zip / tar / gzip / bzip2 / xz scanning. Add your own
  rules, hashes and allowlists without touching code.
- **Always-on watcher** — detects repo clones, pulls/checkouts, new project dirs,
  and downloaded files of any type, and scans them automatically. Its first
  start scans everything already in the watched folders, so malware that was
  on the machine before Guard was installed is found and cleaned too. Bounded
  to <10% RAM.
- **Auto-remediation (default on)** — on a critical hit it *removes the threat*,
  not just alerts:
  - **excises** an injected malicious IIFE from a real source file (keeps the
    imports/config around it),
  - **quarantines** whole-file droppers (a fake `.woff2` that's actually JS) and
    whole-file malware found by the antivirus engine,
  - **strips** `task.allowAutomaticTasks` and `folderOpen` dropper tasks from
    `.vscode`.
  Every change is backed up first and is reversible (`guard restore`).
- **Desktop notifications** — a "Threat neutralized" popup on detection (Windows
  alert into the active session, macOS Notification Center, Linux `notify-send`).
- **OTA auto-update** — the agent checks a signed manifest and updates itself
  (Ed25519-verified, fail-closed, downgrade-protected). No manual step.
- **Malicious-dependency check** — versions matched against a GitHub-advisory
  malware blocklist (120k+ names).
- **Dependency code is scanned too** — a popular package is not a safe one (a
  hijacked release can ship malware under a trusted name), so `guard scan`,
  `guard clean` and the watcher read every file in `node_modules`, its `dist/`
  and `build/` folders included, and clean what they find like any other file.
  The watcher scans a project's `node_modules` on the first start and after
  each install (when `node_modules` or a lockfile changes). This makes scans of
  big projects slower: about 1.5 minutes per 1 GB of dependencies.
- **Optional telemetry** — machines could report install + status to a dashboard.
  Removed after v2.1.0: Guard no longer sends any telemetry.
- **Host IR triage** — reboot/persistence/recon/flood forensics, OS-native.
- **Kernel telemetry (Windows)** — auto-configures Microsoft Sysmon.
- **macOS permissions helper** — raises the native "Allow" prompts for Desktop /
  Documents / Downloads / removable disks.

---

## Commands

| Command | What it does |
|---|---|
| `guard scan <path>` | full tree scan: antivirus engine, fingerprints, disguised droppers, `.vscode` auto-run, workflows, malicious deps |
| `guard scan-git <path>` | the above **plus** every added line across git history |
| `guard open <path>` | pre-open check — is it safe to open this folder in VS Code? |
| `guard av scan <path...>` | general antivirus scan: hash DB + YARA-style rules + heuristics + archives (`--json`, `--quarantine`, `--fail-on-suspicious`) |
| `guard av quarantine list\|restore <id>\|delete <id>` | manage the neutered (encrypted-at-rest) quarantine vault |
| `guard av rules [--validate FILE] [--licenses]` | list the loaded signatures / validate a custom rule file / print the bundled rules' licenses |
| `guard av hash <file>` | print SHA-256 / SHA-1 / MD5 |
| `guard clean <path>` | **remove** injected malware in place (excise/quarantine), backing up first |
| `guard restore <path>` | undo a clean/quarantine from the backup store |
| `guard watch` | the always-on filesystem watcher (what the service runs) |
| `guard triage` | host IR triage (reboots / persistence / recon / flood) |
| `guard sensor` | Windows endpoint sensor: Sysmon + reboot events to alerts (`--selftest` runs anywhere) |
| `guard permissions [request]` | check disk access; on macOS raise the "Allow" prompts |
| `guard notify-test` | show a sample threat popup (verify desktop alerts work) |
| `guard deps update` | refresh the GitHub malware-package blocklist |
| `guard deps check <path>` | check a project's dependencies against the blocklist (`--blocklist FILE` for another one) |
| `guard update` | manual OTA check (the service also does this automatically) |
| `guard install` / `guard uninstall` | set up / remove the auto-start service |
| `guard version` | print version |

Exit codes for scans: `0` clean, `1` infected (a `critical` / malicious finding;
with `guard av scan --fail-on-suspicious` also a suspicious one), `2` usage/error.

---

## Usage

```bash
# Scan a working tree (fast, no git needed)
guard scan /path/to/repo

# Scan the tree AND every added line across all commits/branches
guard scan-git /path/to/repo

# Pre-open gate: exit 1 means DO NOT OPEN this folder in VS Code
guard open /path/to/repo

# Antivirus scan of any files / folders (archives are unpacked and scanned too)
guard av scan ~/Downloads
guard av scan ./release.zip --json            # machine-readable report
guard av scan ~/Downloads --quarantine        # move whole-file threats into the vault
guard av quarantine list                      # ...and bring one back if needed
guard av quarantine restore <id>

# Manually clean an infected repo (the service does this automatically), then undo:
guard clean /path/to/repo
guard restore /path/to/repo/vite.config.ts
```

**Auto-clean is automatic.** You do **not** run `guard clean` by hand in normal
use — the watcher service cleans every detection on its own and pops a
"Threat neutralized" alert. `guard clean` is only the manual/on-demand version.
To make a machine alert-only (no auto-edit), set `"remediate": false` in
`<GUARD_HOME>/watcher.config.json`.

---

## How auto-remediation handles the attack

The attack injects a payload into an otherwise-legitimate file (a malicious IIFE
using `atob(process.env.AUTH_API_KEY)` + `eval(...)` bolted above your real
`vite.config.ts`), and the attacker **amends the original commit** so `git log`
looks clean. So Guard fixes the **working tree by content**, never git history:

- It locates the injected block with a string/comment/template-aware **bracket
  matcher** and removes exactly that span — imports and `export default
  defineConfig(...)` are untouched. If the bounds are ambiguous, the
  whole file is quarantined instead (backed up first; `guard restore` puts it back).
  There is no manual-review state: anything that looks like malware, malicious or
  suspicious, is cut out or quarantined. Files inside operating-system directories
  (`C:\Windows`, `/usr`, `/System`, ...) are reported but never removed.
- After cleaning, commit the fix forward: `git add -A && git commit -m "remove injected payload"`.
  (Don't reset/cherry-pick — the forged history can't be trusted.)

---

## Antivirus engine (`guard av`)

Besides the incident-specific engines, Guard ships a general anti-malware engine
(built into the `guard` binary, no external dependencies). Every file goes through a layered pipeline:

| Layer | What it does | Can produce |
|---|---|---|
| Content type ID | identifies PE / ELF / Mach-O / archives / scripts by **bytes**, not extension | — |
| Allowlist | known-good SHA-256, trusted path globs, disabled rule ids | CLEAN (stops) |
| Hash DB | exact MD5 / SHA-1 / SHA-256 signatures (JSON or `<hash> <name>` text lists) | MALICIOUS |
| YARA | Real YARA rules (`*.yar` / `*.yara`, compiled by yara-x in the Rust core, with the `pe`, `elf`, `macho`, `dotnet`, `math`, `hash` modules and more). Drop a rule file into `~/.guard/av/` or a `--signatures` directory. A rule reports SUSPICIOUS unless its meta says `verdict = "malicious"`; `whole_file = true` marks it safe to quarantine; disable one with `yara:<file stem>.<rule>` in an allowlist. About 2,300 community rules are built in ([data/yara](data/yara/README.md): sources, licenses, how they were picked; `guard av rules --licenses`); they add about 3 s to each engine start, and `GUARD_COMMUNITY_RULES=0` leaves them out | MALICIOUS / SUSPICIOUS |
| Rules | JSON rules (the original format, kept for compatibility): text (ascii/wide/nocase), hex with `??` / `[n-m]` jumps / `(a\|b)`, regex; boolean conditions (`all`/`any`/`at_least`/`at`/`count`/`filesize`) | MALICIOUS / SUSPICIOUS |
| Heuristics | PE packers, encrypted executable sections, W+X sections, entry point outside code, process-injection / hollowing / keylogger API sets, ELF LD-preload rootkits, script obfuscation (encoded-blob exec, `_0x` obfuscator, char-code exec), PowerShell encoded/hidden/AMSI tampering, double/RTLO/masquerading filenames | SUSPICIOUS, MALICIOUS only when ≥3 strong independent indicators agree |
| Archives | recursive zip / tar / gzip / bzip2 / xz, in memory, bomb-safe (depth, member count, size and ratio limits) | per-member verdicts |

Bundled rules cover: EICAR, PHP webshells, bash / netcat / Python reverse shells,
Mimikatz, PowerShell download-and-execute cradles and AMSI bypasses, Node and Python
encoded-payload droppers, `base64 -d | sh` droppers, auto-exec VBA downloaders,
coin miners (PUA), ransom notes and npm install scripts that pipe to a shell.

**False-positive policy.** Only exact hashes and high-confidence rules may say
MALICIOUS; heuristics alone top out at SUSPICIOUS. Documentation files (`.md`,
`.rst`, `.txt`, `.html`) are excluded from hack-tool rules, and the engine
allowlists its own signature databases. The test suite enforces **0 false
positives** (not even SUSPICIOUS) over an adversarial benign corpus, the Python
standard library, system binaries and this repository.

**Custom signatures.** Drop `rules*.json`, `hashes*.json` / `hashes*.txt` and
`allowlist*.json` into `~/.guard/av/` (or pass `--signatures DIR`).

**Quarantine.** `guard av scan --quarantine` moves every flagged file, malicious
or suspicious, into a vault where they are XOR-encrypted with a
per-item key — never runnable, never re-detected by other AV — and restorable with
SHA-256 verification. `guard clean` and the watcher cut injected code out of a
source file when they can and quarantine the file when they can't.

The watcher, `guard scan` and `guard clean` all use this engine automatically.

---

## Configuration

`GUARD_HOME` (defaults: `/var/lib/guard` for the Linux/Windows service,
`~/.guard` for the macOS user agent) holds:

- `watcher.config.json` — watch roots, `remediate`, `notify`, poll interval, memory budget
- `alerts.jsonl` — every detection (audit)
- `watcher.log` — activity
- `quarantine/` — backups of everything remediated + `index.jsonl` (for `guard restore`)
- `av-quarantine/` — the antivirus engine's neutered vault (`guard av quarantine ...`)
- `av/` — optional custom signatures: `rules*.json`, `hashes*.json` / `hashes*.txt`,
  `allowlist*.json` (loaded automatically on every scan)

---

## Build from source

The shipped artifact is a single static Rust binary built from `cli/` (on Linux it
links musl, so it runs on any distro, Alpine included, with no shared libraries).
Build it on each target OS with a Rust toolchain (rustup.rs):

```bash
bash build/build.sh                          # Linux needs musl-tools first
./build/dist/guard version
```

Rule matching, YARA and the content heuristics live in the engine core crate
(`core/`, `guard_core`), which `cli/` links in. The AV rule and hash databases
(`data/av-rules.json`, `data/av-hashes.json`) are compiled into the binary by
`cli/build.rs`.

The core also gives the watcher native file-change events (inotify, FSEvents,
ReadDirectoryChangesW), so it reacts to a new file in under a second without
re-walking every watch root. It still runs a full snapshot pass at start, every
`full_rescan_sec` (default 300) and whenever the OS drops events. With
`"native_events": false` in `watcher.config.json` it polls every
`poll_interval_sec` instead. On Linux each watched directory uses one inotify
watch; if `fs.inotify.max_user_watches` runs out, the watcher logs it and polls.

Releases are built for all five platforms by `.github/workflows/release.yml` on a
`git tag vX.Y.Z`, which first runs the full test suite, then signs the OTA manifest
and publishes the GitHub Release.

---

## Testing

```bash
cargo test --locked --manifest-path cli/Cargo.toml       # unit + integration tests (cli/tests/*.rs)
cargo test --manifest-path core/Cargo.toml               # engine core
cargo test --manifest-path release/Cargo.toml            # release signer
GUARD_FP_FULL=1 cargo test --locked --manifest-path cli/Cargo.toml --test detection   # full false-positive sweep
```

The suite covers unit tests per engine, detection-rate tests (every malicious
sample detected, also inside zip / tar.gz / gzip / nested archives), the zero
false-positive sweep (system binaries, the Python standard library if present,
this repo and the binary itself), and integration tests that run the `guard`
binary (AV, scan, commands, updater, watcher, tools) and compare its output with
golden files in `cli/tests/golden/`. The goldens were recorded from the earlier
Python build, so they pin the binary to its behaviour; they are stored base64
(read one with `base64 -d`). Live malware samples are stored base64-encoded and only decoded in
memory, so the repository itself always scans clean. CI runs it on every push and
the release workflow refuses to build if it fails.

---

## Contributing

Contributions are welcome — especially new detection signatures.

1. **Fork** and create a feature branch off `main`.
2. **Signatures are data, not code.** General malware rules and hashes go in
   `data/av-rules.json` / `data/av-hashes.json`, or as YARA in a `*.yar` file
   (validate either with `guard av rules --validate <file>`); incident IOCs go in `signatures.json`
   (fingerprints, dropper paths, `.vscode` rules). No code change needed. Add a
   matching fixture under `testdata/`, or a base64-encoded sample in
   `cli/tests/common/samples.rs` so live signatures never land in the repo.
3. **Add tests / fixtures** for anything you change, and keep false positives at
   zero (clean controls must still pass).
4. Run the engines and the suite locally:
   ```bash
   guard scan testdata/<your-fixture>
   cargo test --locked --manifest-path cli/Cargo.toml
   ```
5. **Open a PR** describing the technique, the signature, and the fixture.

Code layout: `cli/src/main.rs` (entrypoint/CLI) · `cli/src/av/` (antivirus
engine: `engine`, `rules`, `yara`, `heuristics`, `archive`, `hashdb`, `allowlist`,
`quarantine`, `filetype`) · `cli/src/scan/` (`scanner` orchestrator, `fingerprint`,
`vscode`, `magic`, `workflow`, `depbl` detection, `remediate` auto-clean) ·
`cli/src/watch/` (`watcher` service, `memguard` + `store` memory-bounded scanning) ·
`sensor.rs` (Windows sensor) · `deps.rs` (malware blocklist) · `update.rs` (OTA) ·
`install.rs` (service install) · `notify.rs` (alerts) ·
`permissions.rs` (macOS access) · `core/src/` (`guard_core`: rule matching, YARA,
heuristics, native file events) · `release/src/` (`sign-manifest` release signer) ·
`data/` (AV rules and hashes).

Please keep the project's boundaries: it detects, removes injected payloads with a
reversible backup, and reports — it does **not** rewrite remote git history,
force-push, or carry a broad-scope GitHub token on the endpoint.

See also: [Code of Conduct](CODE_OF_CONDUCT.md) · [Contributing](CONTRIBUTING.md) ·
[Privacy Policy](PRIVACY.md).

---

## Code signing

Windows release binaries are Authenticode code-signed. Free code signing for this
open-source project is provided by the **[SignPath Foundation](https://signpath.org)**,
with a certificate issued by SignPath Foundation. (Signing is being enabled for the
project; unsigned builds remain verifiable by the SHA-256 published with each
release.)

---

## The attack, in one paragraph

A JS dropper was committed disguised as a font (`public/fonts/fa-solid-400.woff2`).
A `.vscode/tasks.json` task with `"runOn": "folderOpen"` plus
`"task.allowAutomaticTasks": true` in `settings.json` makes VS Code **auto-execute
that dropper the moment a developer opens the folder — no click required**. The
dropper injects an obfuscated C2 payload / an `eval(proxyInfo)` IIFE (pulling code
from `auth-confirm-ten.vercel.app`) into build/config files, then commits under the
victim's git identity — which is why one attack shows up across dozens of
developers and repos: it re-infects on every folder open. **The endpoint is the
vector — hence Guard.**

A later wave (issue #24) appends a javascript-obfuscator `_0x` loader to the last
line of real configs (`jest.config.js`, `eslint.config.js`, `babel.config.js`),
pushed off-screen by hundreds of spaces and tagged with a short campaign marker,
and plants a base64 C2 URL in `.env`. Guard flags every marker variant, and
`guard clean` cuts the loader off and keeps the config.

Markers and names can change, so Guard also flags any script (JavaScript,
TypeScript, Python, shell, PowerShell) with code hidden after 150 or more
spaces or tabs, whatever the code is called or however its strings are split.
No real code in a sweep of about 70,000 such files did that. In JavaScript and
TypeScript, `guard clean` and the watcher cut the hidden code out and keep the
rest of the file; other files are quarantined, and `guard restore` undoes either.

---

## License

[MIT](LICENSE) © 2026 Syed Bipul Rahman
