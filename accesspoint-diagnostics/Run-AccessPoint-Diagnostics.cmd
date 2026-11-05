@echo off
setlocal
echo SpotiRoute access point protocol diagnostics. No administrator rights required.
echo Keep the current Zapret strategy running and Spotify on its error screen.
echo No sign-in is performed. Settings and account files are not changed.
echo This can take 1-2 minutes.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Collect-AccessPoint-Diagnostics.ps1"
echo.
echo Send back SpotiRoute-AccessPoint-Diagnostics.json from this folder.
pause
