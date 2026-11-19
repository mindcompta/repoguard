@echo off
setlocal
cd /d "%~dp0"
if exist "%~dp0runtime\pythonw.exe" goto bundled
where pyw >nul 2>&1
if not errorlevel 1 goto system_pythonw
call "%~dp0Diagnostic-RepoGuard.bat"
exit /b
:bundled
start "" "%~dp0runtime\pythonw.exe" "%~dp0Lancer-RepoGuard.pyw"
exit /b 0
:system_pythonw
start "" pyw -3 "%~dp0Lancer-RepoGuard.pyw"
exit /b 0
