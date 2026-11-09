@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

rem --- find a Python that really starts (skip broken launchers) ---
set "PY="
for %%C in ("python" "py -3.13" "py -3.12" "py -3.11" "py -3" "py") do (
  if not defined PY (
    %%~C -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>nul && set "PY=%%~C"
  )
)
if not defined PY (
  for /d %%D in ("%LocalAppData%\Programs\Python\Python3*" "%ProgramFiles%\Python3*" "%LocalAppData%\Python\pythoncore-3*") do (
    if not defined PY if exist "%%~D\python.exe" (
      "%%~D\python.exe" -c "import sys" >nul 2>nul && set "PY="%%~D\python.exe""
    )
  )
)
if not defined PY (
  echo [!] No working Python found.
  echo     Install Python 3.12 from https://www.python.org/downloads/
  echo     and tick "Add python.exe to PATH" during setup. Then run this file again.
  pause
  exit /b 1
)
echo Using Python: !PY!
!PY! --version

echo === Installing dependencies ===
!PY! -m pip --version >nul 2>nul || !PY! -m ensurepip --upgrade
!PY! -m pip install --upgrade pip
!PY! -m pip install -r requirements.txt pyinstaller
if errorlevel 1 goto fail

echo === Building ABIRoute.exe ===
!PY! -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin --name ABIRoute --icon icon.ico --add-data "icon.ico;." abi_route.py
if errorlevel 1 goto fail

echo.
echo DONE: %~dp0dist\ABIRoute.exe
pause
exit /b 0

:fail
echo.
echo [!] Build failed. Send the text above to get help.
pause
exit /b 1
