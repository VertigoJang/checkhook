@echo off
rem CheckHook launcher for Windows (wraps packaging\windows\checkhook.ps1)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0packaging\windows\checkhook.ps1" %*
