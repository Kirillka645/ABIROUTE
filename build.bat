@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

echo === [1/4] Checking Go and Node.js ===
where go >nul 2>nul || (
  echo [!] Go 1.24+ not found. Install from https://go.dev/dl/
  pause
  exit /b 1
)
where npm >nul 2>nul || (
  echo [!] Node.js / npm not found. Install from https://nodejs.org/
  pause
  exit /b 1
)

echo === [2/4] Building React + Tailwind UI ===
pushd frontend
call npm install --no-audit --no-fund
if errorlevel 1 ( popd & goto fail )
call npm run build
if errorlevel 1 ( popd & goto fail )
popd

echo === [3/4] Compiling Windows resources and running tests ===
where windres >nul 2>nul && (
  pushd winres
  windres -i abiroute.rc -o ..\rsrc_windows_amd64.syso -O coff
  popd
)
go test ./...
if errorlevel 1 goto fail

echo === [4/4] Building dist\ABIRoute.exe ===
if not exist dist mkdir dist
go build -tags "desktop,production" -trimpath -ldflags "-s -w -H windowsgui" -o dist\ABIRoute.exe .
if errorlevel 1 goto fail

echo.
echo DONE: %~dp0dist\ABIRoute.exe
exit /b 0

:fail
echo.
echo [!] Build failed.
exit /b 1
