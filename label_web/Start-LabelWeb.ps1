param([switch]$UseExistingDatabase, [switch]$AllowLan)
$ErrorActionPreference = 'Stop'
$projectPath = $PSScriptRoot
$pythonPath = Join-Path $projectPath '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw '請先在 label_web 執行 python -m venv .venv，再以 .venv\Scripts\python.exe -m pip install -r requirements.txt 安裝套件。'
}
if ($AllowLan) {
    if ($env:LABELCHECK_PASSWORD.Length -lt 8) { throw '區域網路模式請先設定至少 8 字元的 LABELCHECK_PASSWORD。' }
    $env:LABELCHECK_HOST = '0.0.0.0'
} else { $env:LABELCHECK_HOST = '127.0.0.1' }
$env:PYTHONIOENCODING = 'utf-8'
$env:PORT = '5083'
$launchArguments = @('run.py')
if ($UseExistingDatabase) { $launchArguments += '--existing-database' }
Set-Location -LiteralPath $projectPath
& $pythonPath @launchArguments
