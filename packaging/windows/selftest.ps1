#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Check a CheckHook install end to end (Windows). Run in an elevated PowerShell:
      powershell -ExecutionPolicy Bypass -File packaging\windows\selftest.ps1

.DESCRIPTION
    Safe on a live system: the enforcement test adds and removes 203.0.113.250,
    an address reserved for documentation (RFC 5737), with a 2-minute timeout.
    Nothing else is changed. Paste the whole output when reporting a problem.
    Exit code = number of FAILs.
#>
$ErrorActionPreference = 'Continue'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Data = Join-Path $env:ProgramData 'CheckHook'
$script:Pass = 0; $script:Warn = 0; $script:Fail = 0
function Ok([string]$m)   { $script:Pass++; Write-Host "  [PASS] $m" -ForegroundColor Green }
function Wn([string]$m)   { $script:Warn++; Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Bad([string]$m)  { $script:Fail++; Write-Host "  [FAIL] $m" -ForegroundColor Red }
function Info([string]$m) { Write-Host "  [ -- ] $m" }
function Section([string]$m) { Write-Host ""; Write-Host "== $m ==" }
function Summary { Write-Host ""; Write-Host ("summary: {0} pass, {1} warn, {2} fail" -f $script:Pass, $script:Warn, $script:Fail); exit $script:Fail }
$TestIp = '203.0.113.250'

Push-Location $Root
try {
# ------------------------------------------------------------------ system
Section 'system'
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
Write-Host ("  windows   : {0} (build {1})" -f $os.Caption, $os.BuildNumber)
Write-Host ("  machine   : {0} {1}" -f $cs.Manufacturer, $cs.Model)
$pyFile = Join-Path $Data 'python.txt'
if (-not (Test-Path $pyFile)) { Bad "not installed ($pyFile missing): run packaging\windows\install.ps1"; Summary }
$Py = (Get-Content $pyFile -TotalCount 1).Trim()
if (Test-Path $Py) { Ok "python $Py ($(& $Py --version 2>&1))" } else { Bad "python $Py not found"; Summary }
Write-Host "  checkhook : $(& $Py -m checkhook.diag version 2>&1)"
if (Test-Path (Join-Path $env:SystemRoot 'System32\Npcap\wpcap.dll')) { Ok 'Npcap' } else { Bad 'Npcap missing (https://npcap.com)' }

# ------------------------------------------------------------------ config
Section 'config'
$raw = & $Py -m checkhook.diag config 2>&1
try { $cfg = ($raw | Out-String) | ConvertFrom-Json } catch { $cfg = $null }
if (-not $cfg) { Bad "config does not load: $raw"; Summary }
Ok ("config loads: backend={0} enforce={1} skip=[{2}]" -f $cfg.backend, $cfg.enforce, ($cfg.skip -join ','))
$dev = & $Py -m checkhook.diag device $cfg.iface 2>&1
if ($LASTEXITCODE -eq 0 -and "$dev" -match 'NPF_') { Ok "capture adapter ($($cfg.iface)): $dev" } else { Bad "capture adapter ($($cfg.iface)): $dev" }

# ------------------------------------------------------------------ tasks
Section 'tasks'
foreach ($t in 'checkhookd', 'checkhook-suricata') {
    $task = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    if (-not $task) {
        if ($t -eq 'checkhookd') { Bad "task $t not registered" } else { Info "task $t not registered (no Suricata)" }
        continue
    }
    if ($task.State -eq 'Running') { Ok "task $t running" }
    else { Bad "task $t state: $($task.State) (Start-ScheduledTask $t; log: $Data\logs\checkhookd.log)" }
}
$procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'checkhook\.daemon' }
if ($procs) { Ok "checkhookd process: pid $(@($procs)[0].ProcessId)" } else { Bad 'no checkhookd process' }

# ------------------------------------------------------------------ enforcement
Section "enforcement ($($cfg.backend))"
& $Py -m checkhook.blocklist --backend $cfg.backend add $TestIp --timeout 2m *> $null
$list = (& $Py -m checkhook.blocklist --backend $cfg.backend list 2>&1) | Out-String
if ($list -match [regex]::Escape($TestIp)) { Ok "add $TestIp -> listed" } else { Bad "add $TestIp failed: $list" }
$rules = @(Get-NetFirewallRule -Group 'CheckHook' -ErrorAction SilentlyContinue)
if ($rules.Count -gt 0) { Ok "firewall rules in group CheckHook: $($rules.Count)" } else { Bad 'no firewall rules in group CheckHook after add' }
& $Py -m checkhook.blocklist --backend $cfg.backend remove $TestIp *> $null
$list = (& $Py -m checkhook.blocklist --backend $cfg.backend list 2>&1) | Out-String
if ($list -match [regex]::Escape($TestIp)) { Bad "remove $TestIp failed (expires in 2 min anyway)" } else { Ok "remove $TestIp -> gone" }

# ------------------------------------------------------------------ detection
Section 'detection'
if ((& $Py -m checkhook.diag parse 2>&1) -match 'ok') { Ok 'alert parser reads Suricata eve.json' } else { Bad 'alert parser' }
if (-not $cfg.ids) { Info 'ids disabled in config' }
elseif (Test-Path $cfg.alert) {
    $f = Get-Item $cfg.alert
    Ok ("alert file {0} ({1} KB, last write {2:N0}s ago)" -f $f.FullName, [int]($f.Length / 1KB), ((Get-Date) - $f.LastWriteTime).TotalSeconds)
} else { Wn "alert file $($cfg.alert) not there yet (Suricata not running, or no event yet)" }
if (Test-Path $cfg.model) { Ok "ML model $($cfg.model)" } else { Info "no ML model yet ($($cfg.model))" }
$flows = Get-ChildItem $cfg.flows -Filter *.csv -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
if ($flows) {
    $age = ((Get-Date) - $flows[0].LastWriteTime).TotalSeconds
    if ($age -lt 900) { Ok ("flow log writing: {0} ({1:N0}s ago)" -f $flows[0].Name, $age) }
    else { Wn ("newest flow log is {0:N0}s old: {1}" -f $age, $flows[0].Name) }
} else { Wn "no flow CSV in $($cfg.flows) yet (written after the first finished flows)" }

# ------------------------------------------------------------------ check (LLM)
Section 'check (LLM triage)'
$ctx = & $Py -m checkhook.diag network 2>&1
if ("$ctx" -match 'dns=-') { Wn "could not read this host's DNS servers ($ctx)" } else { Ok "local network: $ctx" }
try {
    $tags = Invoke-RestMethod -Uri ($cfg.host.TrimEnd('/') + '/api/tags') -TimeoutSec 5
    if (@($tags.models | ForEach-Object { $_.name }) -contains $cfg.llm) { Ok "Ollama at $($cfg.host) has model $($cfg.llm)" }
    else { Wn "Ollama at $($cfg.host) is up but model $($cfg.llm) is missing -> ollama pull $($cfg.llm)" }
} catch { Wn "Ollama not reachable at $($cfg.host) (reports will have the local-network part only)" }
& $Py -m checkhook.triage --print-prompt --alert-file $cfg.alert --backend $cfg.backend *> $null
if ($LASTEXITCODE -eq 0) { Ok 'triage builds its prompt' } else { Bad 'triage could not build its prompt' }
} finally { Pop-Location }
Summary
