```batch
@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo Starting Amanah Guard Server + Cloudflare Tunnel...
echo.
echo Server is running on: http://127.0.0.1:8765/
echo Waiting for Cloudflare tunnel...
echo.
start "" cmd /c "py server.py --local"
timeout /t 3 /nobreak
start "" cmd /c "cloudflared tunnel --url http://127.0.0.1:8765"
pause
```
