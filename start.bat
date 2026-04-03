@echo off

echo.
echo =========================================
echo   Crypto Chat  Launcher
echo =========================================
echo.
echo Starting server and clients...
echo.

REM Get the directory where this batch file is located
set SCRIPT_DIR=%~dp0

REM Launch Server in new window
echo [1/3] Launching Server...
start "Crypto Chat - Server" cmd /k "cd /d "%SCRIPT_DIR%" && java Server"

REM Wait 2 seconds to ensure server is ready
timeout /t 2 /nobreak >nul

REM Launch Client 1 in new window
echo [2/3] Launching Client 1...
start "Crypto Chat - Client 1" cmd /k "cd /d "%SCRIPT_DIR%" && java Client"

REM Wait 1 second before launching second client
timeout /t 1 /nobreak >nul

REM Launch Client 2 in new window
echo [3/3] Launching Client 2...
start "Crypto Chat - Client 2" cmd /k "cd /d "%SCRIPT_DIR%" && java Client"

echo.
echo =========================================
echo   All windows launched successfully!
echo =========================================
echo.
echo You should now see 3 windows:
echo   - Server window (accepting connections)
echo   - Client 1 window (ready to chat)
echo   - Client 2 window (ready to chat)
echo.
echo To chat:
echo   1. Click on a client window
echo   2. Type your message
echo   3. Press Enter to send
echo.
echo To exit:
echo   - Type 'exit' in client windows
echo   - Close the server window when done
echo.
echo =========================================
echo.
pause
