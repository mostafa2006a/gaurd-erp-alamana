@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo.
echo ╔════════════════════════════════════════════════════════╗
echo ║   مؤسسة الأمانة - تطبيق إدارة الحراسة والحسابات      ║
echo ╚════════════════════════════════════════════════════════╝
echo.
echo جاري التشغيل...
echo.

set "FOUND_PY="
py --version >nul 2>&1 && set "FOUND_PY=py"
if not defined FOUND_PY python --version >nul 2>&1 && set "FOUND_PY=python"
if not defined FOUND_PY (
    echo ❌ خطأ: Python غير مثبت أو لم يُضف إلى PATH
    echo    ثبّت Python من python.org واختر "Add to PATH"
    pause
    exit /b 1
)

cloudflared --version >nul 2>&1
if errorlevel 1 (
    echo ❌ خطأ: Cloudflare tunnel (cloudflared) غير مثبت
    echo    شغّل هذا الأمر أولًا:
    echo    winget install --id Cloudflare.cloudflared
    pause
    exit /b 1
)

echo ✓ Python جاهز
echo ✓ Cloudflare tunnel جاهز
echo.
echo جاري فتح نافذتي الخادم والنفق...
echo.

start "Amanah Guard Server" /min cmd /c "title Amanah Guard Server & %FOUND_PY% server.py --local & pause"
timeout /t 2 /nobreak >nul

start "Cloudflare Tunnel" /min cmd /c "title Cloudflare Tunnel & cloudflared tunnel --url http://127.0.0.1:8765"

timeout /t 3 /nobreak >nul

echo.
echo ╔════════════════════════════════════════════════════════╗
echo ║  ✓ الخادم يعمل على: http://127.0.0.1:8765/          ║
echo ║  ⏳ في نافذة "Cloudflare Tunnel" ستظهر رابط HTTPS    ║
echo ║  📋 انسخ الرابط والصقه في المتصفح                    ║
echo ║                                                        ║
echo ║  لإيقاف الخادم:                                       ║
echo ║  • أغلق النافذتين المصغرة (Taskbar)                  ║
echo ║  • أو اضغط Ctrl+C في كل نافذة                       ║
echo ╚════════════════════════════════════════════════════════╝
echo.

pause
