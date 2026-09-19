@echo off
setlocal enabledelayedexpansion
rem Start all four Lab 1 services in the background, one log file each.
rem Windows equivalent of scripts\run_all.sh.
rem
rem   scripts\run_all.cmd            start every service
rem   scripts\run_all.cmd verifier rp   start only the ones named

set "ROOT=%~dp0.."
cd /d "%ROOT%" || exit /b 1
set "RUNDIR=%ROOT%\run"
if not exist "%RUNDIR%" mkdir "%RUNDIR%"

if not exist ".env" (
    echo no .env - copy .env.example to .env and fill it in first
    exit /b 1
)

where python >nul 2>nul
if errorlevel 1 (
    echo no python on PATH
    exit /b 1
)

set "WANTED=%*"
if "%WANTED%"=="" set "WANTED=subject csp verifier rp"

for %%S in (%WANTED%) do call :start_one %%S

rem Give them a moment, then say which ones actually answer. `ping` rather
rem than `timeout`: timeout needs a real console and errors out when this
rem script is invoked from a non-interactive context.
ping -n 3 127.0.0.1 >nul
echo.
echo == health ==
set /a FAILED=0
for %%S in (%WANTED%) do call :check_health %%S

echo.
if !FAILED! GTR 0 (
    echo !FAILED! not answering
) else (
    echo all requested services up: %WANTED%
)

endlocal
exit /b 0

rem -- module_for: %1=service name -> sets MODULE, empty if unknown ----------
:module_for
set "MODULE="
if /I "%~1"=="subject"  set "MODULE=services.subject.main"
if /I "%~1"=="csp"      set "MODULE=services.csp.main"
if /I "%~1"=="verifier" set "MODULE=services.verifier"
if /I "%~1"=="rp"       set "MODULE=services.rp"
goto :eof

rem -- start_one: %1=service name ---------------------------------------------
:start_one
set "NAME=%~1"
call :module_for "%NAME%"
if "%MODULE%"=="" (
    echo   unknown service: %NAME%
    goto :eof
)

set "PIDFILE=%RUNDIR%\%NAME%.pid"
if exist "%PIDFILE%" (
    set /p OLDPID=<"%PIDFILE%"
    tasklist /FI "PID eq !OLDPID!" 2>nul | find "!OLDPID!" >nul
    if not errorlevel 1 (
        echo   %NAME% already running ^(pid !OLDPID!^)
        goto :eof
    )
)

for /f "usebackq delims=" %%P in (`python -c "import sys; sys.path.insert(0, '.'); from shared import config; print(config.port_for('%NAME%'))"`) do set "PORT=%%P"

rem A service started by hand - or a partner's copy on the same host - holds
rem the port without a pidfile here, and launching a second one just fails
rem obscurely.
netstat -ano | findstr /R /C:":!PORT! .*LISTENING" >nul
if not errorlevel 1 (
    echo   %NAME% NOT started - port !PORT! is already held
    echo             whose: netstat -ano ^| findstr :!PORT!
    goto :eof
)

set "LOG=%RUNDIR%\%NAME%.log"
rem Built as one plain variable, with no quoting of its own: nested quotes on
rem this line (e.g. to protect a path with spaces) confuse cmd's redirection
rem parsing enough to make `>` apply to this `set` instead of to the process
rem wmic launches - the exact symptom was a truncated PYCMD and no log file.
set "PYCMD=cmd /c python -m %MODULE% > %LOG% 2>&1"
set "WMICOUT=%RUNDIR%\%NAME%.wmic.tmp"
rem wmic's Create() does not inherit this script's working directory - it has
rem to be passed explicitly, or "No module named 'services'" is what starts.
wmic process call create "%PYCMD%","%ROOT%" > "%WMICOUT%" 2>nul
set "NEWPID="
for /f "tokens=3" %%I in ('findstr /C:"ProcessId" "%WMICOUT%"') do set "NEWPID=%%I"
set "NEWPID=%NEWPID:;=%"
del "%WMICOUT%" >nul 2>nul
if "%NEWPID%"=="" (
    echo   %NAME% failed to start - see %LOG%
    goto :eof
)
> "%PIDFILE%" echo %NEWPID%
echo   started %NAME% (pid %NEWPID%) -^> run\%NAME%.log
goto :eof

rem -- check_health: %1=service name, increments FAILED on trouble -----------
:check_health
set "NAME=%~1"
call :module_for "%NAME%"
if "%MODULE%"=="" goto :eof

for /f "usebackq delims=" %%P in (`python -c "import sys; sys.path.insert(0, '.'); from shared import config; print(config.port_for('%NAME%'))"`) do set "PORT=%%P"

set "OUT=%RUNDIR%\%NAME%.health.tmp"
python -c "import json, sys, urllib.request; d=json.load(urllib.request.urlopen('http://127.0.0.1:%PORT%/health', timeout=3)); print(json.dumps(d)); sys.exit(0 if d.get('service') == '%NAME%' else 1)" > "%OUT%" 2>&1
if errorlevel 1 (
    echo   %NAME%   DOWN
    for /f "usebackq delims=" %%L in ("%OUT%") do echo             %%L
    echo             see run\%NAME%.log
    set /a FAILED+=1
) else (
    for /f "usebackq delims=" %%L in ("%OUT%") do echo   %NAME%   ok    %%L
)
del "%OUT%" >nul 2>nul
goto :eof
