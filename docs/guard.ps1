# Guard installer (Windows). Served at https://security.sparktech.agency/guard.ps1
#   Run in an ELEVATED PowerShell (Admin):
#     irm https://security.sparktech.agency/guard.ps1 | iex
#
# Downloads guard-windows-<arch>.exe from GitHub Releases, verifies its SHA-256,
# installs to C:\Program Files\Guard, adds it to PATH, and registers an auto-start
# scheduled task that runs `guard watch`. HTTPS only. ASCII-only for PS 5.1.

$ErrorActionPreference = 'Stop'
$Releases   = if ($env:GUARD_BASE_URL) { $env:GUARD_BASE_URL } else { 'https://github.com/Syed-Bipul-Rahman/Security-Guard/releases/latest/download' }
$InstallDir = 'C:\Program Files\Guard'
$Bin        = Join-Path $InstallDir 'guard.exe'

# require elevation (installs to Program Files + registers a task)
$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Error "Run this in an elevated PowerShell (Run as administrator)."; return }

# detect arch -> asset name
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { 'x64' } 'ARM64' { 'arm64' } 'x86' { 'x64' } default { 'x64' }
}
$asset = "guard-windows-$arch.exe"
Write-Host "Guard installer: windows-$arch"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# Trust Guard in Microsoft Defender BEFORE downloading, so the agent (an unsigned,
# self-updating file scanner — exactly what heuristics flag) isn't quarantined or
# blocked. Best-effort: skip quietly if Defender is off or centrally managed.
try {
  Add-MpPreference -ExclusionPath $InstallDir -ErrorAction Stop
  Add-MpPreference -ExclusionProcess 'guard.exe' -ErrorAction SilentlyContinue
  Write-Host "Defender: trusted $InstallDir (exclusion added)"
} catch {
  Write-Host "Defender: could not add exclusion (off or managed policy) - continuing"
}

$tmp = Join-Path $env:TEMP $asset
Write-Host "Downloading $asset ..."
Invoke-WebRequest -Uri "$Releases/$asset" -OutFile $tmp -UseBasicParsing

# verify checksum (fail closed). Download the .sha256 to a file and read it as text:
# GitHub serves release assets as octet-stream, so Invoke-WebRequest's .Content is a
# byte[] and calling .Trim() on it throws. -OutFile avoids that.
$want = $null
try {
  $shaFile = "$tmp.sha256"
  Invoke-WebRequest -Uri "$Releases/$asset.sha256" -OutFile $shaFile -UseBasicParsing
  $want = ((Get-Content $shaFile -Raw).Trim() -split '\s+')[0]
  Remove-Item $shaFile -Force -ErrorAction SilentlyContinue
} catch { $want = $null }
if (-not $want) { Remove-Item $tmp -Force; Write-Error "No checksum published for $asset - refusing to install unverified binary."; return }
$have = (Get-FileHash -Path $tmp -Algorithm SHA256).Hash.ToLower()
if ($want.ToLower() -ne $have) { Remove-Item $tmp -Force; Write-Error "CHECKSUM MISMATCH (want $want, got $have) - aborting."; return }
Write-Host "checksum OK"

# stop any running instance so guard.exe isn't locked (a reinstall over a running
# service would otherwise fail to overwrite the binary)
Stop-ScheduledTask -TaskName 'GuardWatcher' -ErrorAction SilentlyContinue | Out-Null
Stop-ScheduledTask -TaskName 'GuardGitHubWatch' -ErrorAction SilentlyContinue | Out-Null
Get-Process -Name guard -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
if (Test-Path $Bin) { Remove-Item $Bin -Force -ErrorAction SilentlyContinue }
Move-Item -Force $tmp $Bin
Write-Host "installed: $Bin"

# add install dir to system PATH (idempotent)
$sysPath = [Environment]::GetEnvironmentVariable('Path','Machine')
if ($sysPath -notlike "*$InstallDir*") {
  [Environment]::SetEnvironmentVariable('Path', "$sysPath;$InstallDir", 'Machine')
  $env:Path = "$env:Path;$InstallDir"
}

# register auto-start task: `guard watch`, at startup + logon, highest privileges, keep-alive
$action    = New-ScheduledTaskAction -Execute $Bin -Argument 'watch'
$trigStart = New-ScheduledTaskTrigger -AtStartup
$trigLogon = New-ScheduledTaskTrigger -AtLogOn
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
              -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'GuardWatcher' -Action $action -Trigger @($trigStart,$trigLogon) `
  -Settings $settings -Principal $principal -Force -Description 'Guard supply-chain watcher (auto-start, keep-alive)' | Out-Null
Start-ScheduledTask -TaskName 'GuardWatcher'

# force-push watchdog: `guard github watch` as the signed-in user, since it
# fetches and pushes with that user's git credentials (SYSTEM has none). It
# checks main/master/default branches of the repos under the watched folders
# and puts a force-pushed branch back. Interactive logon: it runs while the
# user is signed in, like their own git would.
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$ghAction    = New-ScheduledTaskAction -Execute $Bin -Argument 'github watch'
$ghTrigger   = New-ScheduledTaskTrigger -AtLogOn -User $me
$ghSettings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
                -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
$ghPrincipal = New-ScheduledTaskPrincipal -UserId $me -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName 'GuardGitHubWatch' -Action $ghAction -Trigger $ghTrigger `
  -Settings $ghSettings -Principal $ghPrincipal -Force -Description 'Guard force-push watchdog (undoes force pushes on main/master)' | Out-Null
Start-ScheduledTask -TaskName 'GuardGitHubWatch' -ErrorAction SilentlyContinue

# --- auto-configure Sysmon (Microsoft-signed kernel telemetry) ---
# Installs Sysmon (or updates its config if already present) using the config
# bundled inside the Guard binary. Best-effort: Guard works fine without it.
function Install-Sysmon {
  param([string]$Bin, [string]$Arch)
  try {
    $work = Join-Path $env:TEMP 'guard-sysmon'
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $cfg = Join-Path $work 'sysmon-config.xml'
    & $Bin sysmon-config $cfg | Out-Null           # config comes from the binary
    if (-not (Test-Path $cfg)) { throw 'could not export sysmon config' }

    $exeName   = if ($Arch -eq 'arm64') { 'Sysmon64a.exe' } else { 'Sysmon64.exe' }
    $sysmonExe = Join-Path $work $exeName
    if (-not (Test-Path $sysmonExe)) {
      $zip = Join-Path $work 'Sysmon.zip'
      Invoke-WebRequest 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip -UseBasicParsing
      Expand-Archive $zip -DestinationPath $work -Force
    }
    $svc = Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($svc) {
      & $sysmonExe -accepteula -c $cfg | Out-Null
      Write-Host "Sysmon: updated to Guard config (already installed)"
    } else {
      & $sysmonExe -accepteula -i $cfg | Out-Null
      Write-Host "Sysmon: installed with Guard config (kernel telemetry active)"
    }
  } catch {
    Write-Host "Sysmon: auto-configure skipped ($($_.Exception.Message)) - Guard still works without it"
  }
}
Install-Sysmon -Bin $Bin -Arch $arch

Write-Host ""
Write-Host "Done. Guard is installed, trusted in Defender, and the GuardWatcher task is running."
Write-Host "Open a NEW terminal, then try:  guard version   |   guard scan .   |   guard triage"
