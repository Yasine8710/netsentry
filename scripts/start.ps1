# One-command local start: builds the UI if needed and serves everything on http://127.0.0.1:8000
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location "$root\backend"
if (-not (Test-Path ".venv")) {
    python -m venv .venv
    & .\.venv\Scripts\python.exe -m pip install -e ".[dev]"
}
if (-not (Test-Path "$root\frontend\dist\index.html")) {
    Push-Location "$root\frontend"
    npm install
    npm run build
    Pop-Location
}
Write-Host "NetSentry: http://127.0.0.1:8000  (API docs: /docs)"
& .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
