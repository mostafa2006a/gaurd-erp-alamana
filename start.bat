@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PY=
where py >nul 2>nul && set PY=py
if not defined PY where python >nul 2>nul && set PY=python
if not defined PY (
  echo Python is required. Install it from python.org then run this file again.
  pause
  exit /b 1
)
start "" /min cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:8765/"
%PY% server.py
pause
