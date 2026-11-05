@echo off
setlocal
echo SpotiRoute desktop sign-in diagnostics. No administrator rights required.
echo Keep Spotify on its login/error screen and keep Zapret enabled.
echo Please keep current network settings unchanged. This may take 1-2 minutes.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Collect-Desktop-Diagnostics.ps1"
echo.
echo Send back SpotiRoute-Desktop-Diagnostics.json from this folder.
pause