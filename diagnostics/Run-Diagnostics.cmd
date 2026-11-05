@echo off
setlocal
echo SpotiRoute connection diagnostics. Administrator rights are not required.
echo Keep the current Zapret/VPN settings unchanged for this check.
echo This may take about one minute.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Collect-Diagnostics.ps1"
echo.
echo Send back SpotiRoute-Diagnostics.json from this folder.
pause