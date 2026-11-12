<#
    checkhook.ps1 — CheckHook launcher for Windows (banner, menu, commands).
    Usually started from the Start Menu shortcut or .\checkhook.cmd in the repo.
#>
param(
    [Parameter(Position = 0)][string]$Command = 'help',
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Data = Join-Path $env:ProgramData 'CheckHook'
Set-Location $Root

function Get-Python {
    $saved = Join-Path $Data 'python.txt'
    if (Test-Path $saved) { return (Get-Content $saved -TotalCount 1).Trim() }
    if (Get-Command py.exe -ErrorAction SilentlyContinue) { return 'py.exe' }
    return 'python.exe'
}
$Py = Get-Python

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Need-Admin {
    if (-not (Test-Admin)) {
        Write-Host '! this command changes the firewall or CheckHook data; run PowerShell as administrator.' -ForegroundColor Red
        exit 1
    }
}

function Show-Banner {
    $ver = (Select-String -Path (Join-Path $Root 'checkhook\__init__.py') -Pattern '__version__ = "(.*)"').Matches[0].Groups[1].Value
    $lines = @(
        @(' ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗', '██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗'),
        @('██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝', '██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝'),
        @('██║     ███████║█████╗  ██║     █████╔╝ ', '███████║██║   ██║██║   ██║█████╔╝'),
        @('██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ', '██╔══██║██║   ██║██║   ██║██╔═██╗'),
        @('╚██████╗██║  ██║███████╗╚██████╗██║  ██╗', '██║  ██║╚██████╔╝╚██████╔╝██║  ██╗'),
        @(' ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝', '╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝')
    )
    Write-Host ''
    foreach ($l in $lines) {
        Write-Host (' ' + $l[0]) -ForegroundColor Gray -NoNewline
        Write-Host $l[1] -ForegroundColor Red
    }
    Write-Host ''
    $left = "   v$ver"; $right = "by VertigoJang · github.com/VertigoJang"
    Write-Host ($left + (' ' * [Math]::Max(2, 75 - $left.Length - $right.Length)) + $right) -ForegroundColor DarkGray
    Write-Host ''
}

function Show-Menu {
    Show-Banner
    Write-Host '  USAGE   checkhook <command> [options]' -ForegroundColor White
    Write-Host ''
    Write-Host '  ENFORCEMENT  (Windows Defender Firewall, group "CheckHook")' -ForegroundColor White
    Write-Host '    status            show the live blocklist'
    Write-Host '    block <ip>        block an IP  (--timeout 1h)            (admin)'
    Write-Host '    unblock <ip>      remove a block                         (admin)'
    Write-Host '    flush             remove all blocks                      (admin)'
    Write-Host ''
    Write-Host '  DAEMON (checkhookd)' -ForegroundColor White
    Write-Host '    services          checkhookd / Suricata task state, enforce, backend'
    Write-Host '    logs              follow the checkhookd log (Ctrl+C to quit)'
    Write-Host '    restart           restart checkhookd (after editing the config) (admin)'
    Write-Host '    report            run the LLM triage now and show it     (admin)'
    Write-Host '    pause / resume    stop / restart training-data logging  (admin)'
    Write-Host '    gui               open the desktop app                   (asks for admin)'
    Write-Host '    stats             collection and detection summary'
    Write-Host '    config            print the effective config'
    Write-Host ''
    Write-Host '  MODEL' -ForegroundColor White
    Write-Host '    dataset ...       ml.make_dataset  (e.g. --flows "C:/ProgramData/CheckHook/flows/*.csv" --label 0)'
    Write-Host '    train ...         ml.train'
    Write-Host '    eval ...          ml.eval'
    Write-Host ''
    Write-Host '  Detectors default to dry-run (enforce: false). Enforcement is never automatic.' -ForegroundColor DarkGray
    Write-Host ''
}

switch ($Command.ToLower()) {
    { $_ -in 'help', '-h', '--help' } { Show-Menu }
    { $_ -in 'version', '-v', '--version' } { Show-Banner }
    'status'   { & $Py -m checkhook.blocklist list @Rest }
    'block'    { Need-Admin; & $Py -m checkhook.blocklist add @Rest }
    'unblock'  { Need-Admin; & $Py -m checkhook.blocklist remove @Rest }
    'flush'    { Need-Admin; & $Py -m checkhook.blocklist flush }
    'services' {
        foreach ($t in 'checkhookd', 'checkhook-suricata') {
            $task = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
            $state = if ($task) { $task.State } else { 'not installed' }
            '  {0,-18} {1}' -f $t, $state
        }
        $cfg = & $Py -m checkhook.service show 2>$null
        '  {0,-18} {1}' -f 'enforce', (($cfg | Select-String '^enforce: (.*)').Matches.Groups[1].Value)
        '  {0,-18} {1}' -f 'backend', (($cfg | Select-String '^backend: (.*)').Matches.Groups[1].Value)
        '  {0,-18} {1}' -f 'firewall rules', @(Get-NetFirewallRule -Group 'CheckHook' -ErrorAction SilentlyContinue).Count
    }
    'logs'     { Get-Content (Join-Path $Data 'logs\checkhookd.log') -Tail 30 -Wait }
    'restart'  {
        Need-Admin
        $all = Get-CimInstance Win32_Process
        $daemon = $all | Where-Object { $_.CommandLine -match 'checkhook\.daemon' }
        foreach ($a in $daemon) {
            $all | Where-Object { $_.ParentProcessId -eq $a.ProcessId } |
                ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        }
        Stop-ScheduledTask -TaskName 'checkhookd' -ErrorAction SilentlyContinue
        Start-ScheduledTask -TaskName 'checkhookd'
        Write-Host 'checkhookd restarted' -ForegroundColor Green
    }
    'report'   {
        Need-Admin
        & $Py -m checkhook.service triage
        $out = Join-Path $Data 'triage\report.txt'
        if (Test-Path $out) { Get-Content $out -Encoding UTF8 }
    }
    'gui'      {
        $pyw = Join-Path (Split-Path $Py) 'pythonw.exe'
        if (-not (Test-Path $pyw)) { $pyw = $Py }
        Start-Process -FilePath $pyw -ArgumentList '-m', 'checkhook.gui' -WorkingDirectory $Root -Verb RunAs
    }
    'stats'    { & $Py -m checkhook.status @Rest }
    'pause'    { Need-Admin; & $Py -m checkhook.collect pause @Rest }
    'resume'   { Need-Admin; & $Py -m checkhook.collect resume }
    'config'   { & $Py -m checkhook.service show }
    'dataset'  { & $Py -m ml.make_dataset @Rest }
    'train'    { & $Py -m ml.train @Rest }
    'eval'     { & $Py -m ml.eval @Rest }
    default    {
        Write-Host "unknown command: $Command" -ForegroundColor Red
        Show-Menu
        exit 2
    }
}
