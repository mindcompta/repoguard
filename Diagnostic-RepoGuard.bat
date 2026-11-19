@echo off
setlocal
cd /d "%~dp0"
if exist "%~dp0runtime\python.exe" goto bundled
where py >nul 2>&1
if not errorlevel 1 goto python_launcher
where python >nul 2>&1
if not errorlevel 1 goto python_command
echo Python est introuvable. Si vous utilisez l'archive source, installez Python 3.10 ou plus recent.
pause
exit /b 2
:bundled
"%~dp0runtime\python.exe" -m repoguard web
goto finished
:python_launcher
py -3 -m repoguard web
goto finished
:python_command
python -m repoguard web
:finished
if errorlevel 1 (
    echo.
    echo RepoGuard n'a pas pu demarrer. Verifiez que l'archive a ete entierement extraite.
    pause
    exit /b 2
)
endlocal
