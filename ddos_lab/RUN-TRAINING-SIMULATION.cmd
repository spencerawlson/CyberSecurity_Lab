@echo off
REM ==========================================================================
REM  DDoS IR Training Simulation -- SAFE, honest click-to-run launcher.
REM  This is a detection-training tool, NOT an attack tool and NOT disguised:
REM    * the file name says exactly what it is
REM    * the victim and the generator both refuse any target except 127.0.0.1
REM    * it prints a "TRAINING SIMULATION" banner before doing anything
REM  Double-click to run the drill on a lab machine.
REM ==========================================================================
setlocal
title DDoS IR Training Simulation (SAFE)
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (set "PY=py") else (set "PY=python")

echo Launching the SAFE DDoS IR training simulation...
echo (Training tool, not an attack tool. All traffic stays on 127.0.0.1.)
echo.

%PY% "%~dp0ddos_sim.py" run --announce --attack volumetric
set "RC=%errorlevel%"

echo.
echo Simulation finished (exit code %RC%).
echo To see the blue-team detection guide, run:
echo     %PY% "%~dp0ddos_sim.py" detect
echo To review what happened, run:
echo     %PY% "%~dp0ddos_sim.py" report
echo To try the slow-rate variant, run:
echo     %PY% "%~dp0ddos_sim.py" run --announce --attack slowloris
echo.
pause
endlocal
