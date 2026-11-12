#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install CheckHook on Windows (run in an elevated PowerShell).

.DESCRIPTION
    * checks Python 3 and Npcap, installs the Python packages
    * creates C:\ProgramData\CheckHook (config, logs, flows, Suricata output),
      writable only by Administrators and SYSTEM
    * if Suricata is installed: adds CheckHook's rules, validates the config and
      registers the "checkhook-suricata" task (starts at boot)
    * registers the "checkhookd" task (SYSTEM, starts at boot): IDS bridge,
      ML/flow logging, block expiry, hourly LLM triage
    * adds a Start Menu shortcut

    The config starts with enforce: false, so nothing is blocked until you
    change it.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File packaging\windows\install.ps1
    powershell -ExecutionPolicy Bypass -File packaging\windows\install.ps1 -Adapter "Wi-Fi"
    powershell -ExecutionPolicy Bypass -File packaging\windows\install.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [string]$Adapter = 'auto',
    [switch]$NoSuricata,
    [switch]$SkipPip
)

$ErrorActionPreference = 'Stop'
$Root      = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Data      = Join-Path $env:ProgramData 'CheckHook'
$Conf      = Join-Path $Data 'checkhook.yaml'
$SuriOut   = Join-Path $Data 'suricata'
$DaemonTask = 'checkhookd'
$SuriTask   = 'checkhook-suricata'
$Shortcut  = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\CheckHook.lnk'
$ShortcutTerm = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\CheckHook (terminal).lnk'

function Say([string]$Msg, [string]$Color = 'Gray') { Write-Host $Msg -ForegroundColor $Color }
function Fail([string]$Msg) { Write-Host "[x] $Msg" -ForegroundColor Red; exit 1 }

function Stop-CheckHookProcesses {
    # checkhookd and its nfstream worker processes, and CheckHook's Suricata process
    $all = Get-CimInstance Win32_Process
    $roots = $all | Where-Object { $_.CommandLine -match 'checkhook\.daemon' -or
                                   ($_.Name -eq 'suricata.exe' -and $_.CommandLine -match 'checkhook\.rules') }
    foreach ($r in $roots) {
        $all | Where-Object { $_.ParentProcessId -eq $r.ProcessId } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Stop-Process -Id $r.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

function Remove-CheckHookTask([string]$Name) {
    if (Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $Name -Confirm:$false
    }
}

# ------------------------------------------------------------------ uninstall
if ($Uninstall) {
    Remove-CheckHookTask $DaemonTask
    Remove-CheckHookTask $SuriTask
    Stop-CheckHookProcesses
    Get-NetFirewallRule -Group 'CheckHook' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Remove-Item $Shortcut, $ShortcutTerm -ErrorAction SilentlyContinue
    Say "CheckHook removed (tasks, firewall rules, shortcut). Settings and data are kept in $Data." Green
    exit 0
}

# ------------------------------------------------------------------ python
function Find-Python {
    if (Get-Command py.exe -ErrorAction SilentlyContinue) {
        $exe = & py.exe -3 -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $exe) { return $exe.Trim() }
    }
    $p = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($p -and $p.Source -notmatch 'WindowsApps') { return $p.Source }   # skip the Store alias
    return $null
}

$Python = Find-Python
if (-not $Python) {
    Fail "Python 3 not found. Install it (e.g. winget install Python.Python.3.12) and run this again."
}
$ver = & $Python -c "import sys; print('%d.%d' % sys.version_info[:2])"
Say "[i] python : $Python ($ver)"
if ([version]$ver -lt [version]'3.9') { Fail "Python 3.9 or newer is required (found $ver)." }

# ------------------------------------------------------------------ npcap
$Npcap = Join-Path $env:SystemRoot 'System32\Npcap\wpcap.dll'
if (-not (Test-Path $Npcap)) {
    Fail "Npcap not found. Install it from https://npcap.com (default options) and run this again."
}
Say "[i] npcap  : $Npcap"

# ------------------------------------------------------------------ packages
if (-not $SkipPip) {
    Say "[i] installing Python packages (nfstream, scikit-learn, joblib, pyyaml, pandas)..."
    & $Python -m pip install --upgrade --disable-pip-version-check nfstream scikit-learn joblib pyyaml pandas
    if ($LASTEXITCODE -ne 0) {
        Fail "pip failed. If nfstream has no wheel for Python $ver, install Python 3.12 and run this again."
    }
    # desktop app (optional: the firewall works without it)
    & $Python -m pip install --upgrade --disable-pip-version-check PySide6-Essentials
    if ($LASTEXITCODE -ne 0) { Say '[!] PySide6 could not be installed: the desktop app will not open (the firewall still works).' Yellow }
}
Push-Location $Root
try {
    & $Python -c "import checkhook.daemon, nfstream, sklearn, yaml" 2>$null
    if ($LASTEXITCODE -ne 0) { Fail "Python packages are not importable; run without -SkipPip." }
} finally { Pop-Location }

# ------------------------------------------------------------------ data dir
foreach ($d in $Data, $SuriOut, (Join-Path $Data 'flows'), (Join-Path $Data 'triage'), (Join-Path $Data 'logs')) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}
# Administrators + SYSTEM: full control; Users: read only (SIDs: locale-independent)
& icacls.exe $Data /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
Set-Content -Path (Join-Path $Data 'python.txt') -Value $Python -Encoding ASCII

if (Test-Path $Conf) {
    Say "[=] keeping existing $Conf"
} else {
    Copy-Item (Join-Path $Root 'packaging\windows\checkhook.example.yaml') $Conf
    if ($Adapter -ne 'auto') {
        (Get-Content $Conf) -replace '^  iface: auto.*$', "  iface: $Adapter" | Set-Content $Conf -Encoding UTF8
    }
    Say "[+] wrote $Conf  (enforce: false)" Green
}

# capture device (same resolution checkhookd uses)
Push-Location $Root
try {
    $env:CHECKHOOK_ADAPTER = $Adapter      # passed via the environment, not spliced into code
    $Device = & $Python -c "import os; from checkhook.winnet import capture_device; print(capture_device(os.environ['CHECKHOOK_ADAPTER']))"
    if ($LASTEXITCODE -ne 0 -or -not $Device) { Fail "could not resolve the network adapter '$Adapter'." }
    $Device = $Device.Trim()
} finally { Pop-Location }
Say "[i] capture: $Device"

# ------------------------------------------------------------------ tasks
function Register-CheckHookTask([string]$Name, [string]$Exe, [string]$Arguments, [string]$Dir, [string]$Description) {
    $action    = New-ScheduledTaskAction -Execute $Exe -Argument $Arguments -WorkingDirectory $Dir
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                   -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
                   -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $Name -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Description $Description -Force | Out-Null
}

Remove-CheckHookTask $DaemonTask
Remove-CheckHookTask $SuriTask
Stop-CheckHookProcesses

# Suricata (optional)
$Suri = Join-Path $env:ProgramFiles 'Suricata\suricata.exe'
$SuriState = 'not installed (signature detection off; ML still works)'
if (-not $NoSuricata -and (Test-Path $Suri)) {
    $SuriYaml = Join-Path (Split-Path $Suri) 'suricata.yaml'
    $Rules    = Join-Path $SuriOut 'checkhook.rules'
    if (-not (Test-Path $Rules)) { Copy-Item (Join-Path $Root 'packaging\suricata\checkhook.rules') $Rules }
    & $Suri -T -c $SuriYaml -s $Rules -l $SuriOut *> (Join-Path $Data 'logs\suricata-test.log')
    if ($LASTEXITCODE -ne 0) {
        Say "[!] Suricata rejected its config; see $Data\logs\suricata-test.log. Suricata task NOT registered." Yellow
        $SuriState = 'config test failed (see logs\suricata-test.log)'
    } else {
        $suriArgs = "-c `"$SuriYaml`" -i `"$Device`" -s `"$Rules`" -l `"$SuriOut`" -k none"
        Register-CheckHookTask $SuriTask $Suri $suriArgs (Split-Path $Suri) 'CheckHook: Suricata IDS writing eve.json for checkhookd'
        Start-ScheduledTask -TaskName $SuriTask
        $SuriState = 'registered and started'
    }
} elseif ($NoSuricata) {
    $SuriState = 'skipped (-NoSuricata)'
}

Register-CheckHookTask $DaemonTask $Python '-m checkhook.daemon' $Root 'checkhookd: IDS bridge, ML detector, block expiry, LLM triage'
Start-ScheduledTask -TaskName $DaemonTask

# ------------------------------------------------------------------ shortcut
$ws  = New-Object -ComObject WScript.Shell
$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
# the app (asks for administrator rights through UAC when opened)
$lnk = $ws.CreateShortcut($Shortcut)
$lnk.TargetPath       = $psExe
$lnk.Arguments        = "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Root\packaging\windows\checkhook.ps1`" gui"
$lnk.WorkingDirectory = $Root
$lnk.IconLocation     = Join-Path $Root 'assets\checkhook.ico'
$lnk.Description      = 'CheckHook AI firewall'
$lnk.Save()
# the terminal launcher (banner + menu)
$lnk = $ws.CreateShortcut($ShortcutTerm)
$lnk.TargetPath       = $psExe
$lnk.Arguments        = "-NoExit -ExecutionPolicy Bypass -File `"$Root\packaging\windows\checkhook.ps1`""
$lnk.WorkingDirectory = $Root
$lnk.IconLocation     = Join-Path $Root 'assets\checkhook.ico'
$lnk.Description      = 'CheckHook AI firewall (terminal)'
$lnk.Save()

Start-Sleep -Seconds 3
$daemonState = (Get-ScheduledTask -TaskName $DaemonTask).State
Say ''
Say "checkhookd         : $daemonState" Green
Say "checkhook-suricata : $SuriState"
Say "config           : $Conf   (enforce: false = dry-run)"
Say "log                : $Data\logs\checkhookd.log"
Say "launcher         : Start Menu > CheckHook, or .\checkhook.cmd in $Root"
Say "uninstall        : powershell -ExecutionPolicy Bypass -File packaging\windows\install.ps1 -Uninstall"
