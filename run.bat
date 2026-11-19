@echo off
rem NetWatch for Windows - double-click, or:  run.bat --demo   (see run.ps1 for all options)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
if errorlevel 1 pause
