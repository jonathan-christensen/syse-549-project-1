@echo off
setlocal enabledelayedexpansion
rem Stop the services started by run_all.cmd.
rem
rem   scripts\stop_all.cmd           stop everything
rem   scripts\stop_all.cmd rp        stop only the ones named

set "ROOT=%~dp0.."
cd /d "%ROOT%" || exit /b 1
set "RUNDIR=%ROOT%\run"

set "WANTED=%*"
if "%WANTED%"=="" set "WANTED=subject csp verifier rp"

for %%S in (%WANTED%) do call :stop_one %%S

endlocal
exit /b 0

:stop_one
set "NAME=%~1"
set "PIDFILE=%RUNDIR%\%NAME%.pid"
if exist "%PIDFILE%" (
    set /p PID=<"%PIDFILE%"
    tasklist /FI "PID eq !PID!" 2>nul | find "!PID!" >nul
    if not errorlevel 1 (
        rem /T kills the whole tree: the cmd wrapper run_all started AND the
        rem python process it launched, not just the wrapper.
        taskkill /PID !PID! /T /F >nul 2>nul
        echo   stopped %NAME% ^(pid !PID!^)
    ) else (
        echo   %NAME% was not running ^(stale pid !PID!^)
    )
    del "%PIDFILE%" >nul 2>nul
) else (
    echo   %NAME% not started by run_all.cmd
)
goto :eof
