@echo off
chcp 65001 >nul
net session >nul 2>&1
if errorlevel 1 (
  echo Run this file as Administrator: right-click then "Run as administrator".
  pause
  exit /b 1
)
netsh advfirewall firewall add rule name="Amanah Guard 8765" dir=in action=allow protocol=TCP localport=8765 profile=private
echo Done. Other office PCs can now open the address shown by start.bat.
pause
