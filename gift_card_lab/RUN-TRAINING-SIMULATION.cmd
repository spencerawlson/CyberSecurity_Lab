@echo off
REM ==========================================================================
REM  Gift-Card IR Training Simulation -- SAFE, honest click-to-run launcher.
REM  This is a detection-training tool, NOT malware and NOT disguised:
REM    * the file name says exactly what it is
REM    * it only talks to 127.0.0.1
REM    * it prints a "TRAINING SIMULATION" banner before doing anything
REM  Double-click to run the exercise on a lab machine.
REM ==========================================================================
setlocal
title Gift-Card IR Training Simulation (SAFE)
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (set "PY=py") else (set "PY=python")

echo Launching the SAFE gift-card IR training simulation...
echo (Training tool, not malware. All activity stays on 127.0.0.1.)
echo.

%PY% "%~dp0gift_card_lab.py" run --announce --auto-serve
set "RC=%errorlevel%"

echo.
echo Simulation finished (exit code %RC%).
echo To see the blue-team detection guide, run:
echo     %PY% "%~dp0gift_card_lab.py" detect
echo To review what happened, run:
echo     %PY% "%~dp0gift_card_lab.py" report
echo.
pause
endlocal
