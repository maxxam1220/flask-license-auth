@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Please run run_local.ps1 first to install the Python environment.
  pause
  exit /b 1
)
set APP_ENV=development
set DEMO_MODE=1
set DATABASE_URL=sqlite:///preview.sqlite3
set PUBLIC_BASE_URL=http://127.0.0.1:5087
if not exist "instance\preview.sqlite3" (
  ".venv\Scripts\python.exe" -m flask --app app seed-demo
  if errorlevel 1 exit /b 1
)
echo Local preview only: http://127.0.0.1:5087
echo Local demo credentials:
type "instance\preview-access.txt"
echo.
echo Press Ctrl+C to stop.
".venv\Scripts\python.exe" -m waitress --host=127.0.0.1 --port=5087 app:application
endlocal
