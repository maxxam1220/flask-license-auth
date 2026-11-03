[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 5087,
    [switch]$Install,
    [switch]$CreateAdmin
)

$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$venvPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
$requirementsPath = Join-Path $projectRoot 'requirements.txt'
$requirementsStamp = Join-Path $projectRoot '.venv\patrol-requirements.sha256'
$previousEnvironment = @{}
foreach ($variableName in @('APP_ENV', 'DEMO_MODE', 'DATABASE_URL', 'PUBLIC_BASE_URL', 'IMPORT_SAFETY_POINTS')) {
    $previousEnvironment[$variableName] = [Environment]::GetEnvironmentVariable($variableName, 'Process')
}

Push-Location -LiteralPath $projectRoot
try {
    if (-not (Test-Path -LiteralPath $venvPython)) {
        Write-Host 'Creating a local Python environment...'
        & python -m venv (Join-Path $projectRoot '.venv')
        if ($LASTEXITCODE -ne 0) { throw 'Python 3.12 or later is required.' }
    }

    $requirementsHash = (Get-FileHash -LiteralPath $requirementsPath -Algorithm SHA256).Hash
    $savedHash = if (Test-Path -LiteralPath $requirementsStamp) {
        (Get-Content -LiteralPath $requirementsStamp -Raw).Trim()
    } else { '' }
    if ($Install -or $requirementsHash -ne $savedHash) {
        & $venvPython -m pip install -r $requirementsPath
        if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
        Set-Content -LiteralPath $requirementsStamp -Value $requirementsHash -Encoding ASCII
    }

    # This launcher is local-only and intentionally ignores an inherited database URL.
    $localDatabase = (Join-Path $projectRoot 'instance\patrol.sqlite3').Replace('\', '/')
    $env:APP_ENV = 'development'
    $env:DEMO_MODE = 'false'
    $env:IMPORT_SAFETY_POINTS = '0'
    $env:DATABASE_URL = 'sqlite:///' + $localDatabase
    $env:PUBLIC_BASE_URL = "http://127.0.0.1:$Port"

    & $venvPython -m flask --app app init-db
    if ($LASTEXITCODE -ne 0) { throw 'Local database initialization failed.' }

    $adminCheck = @'
from app import application
from models import User
with application.app_context():
    print('present' if User.query.filter_by(role='admin', active=True).first() else 'missing')
'@
    $adminState = (& $venvPython -c $adminCheck | Select-Object -Last 1)
    if ($LASTEXITCODE -ne 0) { throw 'Could not check the local administrator account.' }
    if ($CreateAdmin -or $adminState -eq 'missing') {
        Write-Host 'Create an administrator. Enter a unique password when prompted.'
        & $venvPython -m flask --app app create-admin --username admin --name Admin
        if ($LASTEXITCODE -ne 0) { throw 'Administrator setup was not completed.' }
    }

    Write-Host "Local preview: http://127.0.0.1:$Port"
    Write-Host 'This address is available only on this computer. Press Ctrl+C to stop.'
    & $venvPython -m waitress --host=127.0.0.1 --port=$Port app:application
    if ($LASTEXITCODE -ne 0) { throw 'The local server stopped with an error.' }
} finally {
    foreach ($variableName in $previousEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($variableName, $previousEnvironment[$variableName], 'Process')
    }
    Pop-Location
}
