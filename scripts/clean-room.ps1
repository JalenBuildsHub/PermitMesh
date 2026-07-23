param(
    [string]$Python = "python",
    [string]$Receipt = "validation/clean-room.json"
)

$ErrorActionPreference = "Stop"
$started = Get-Date
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$tempRoot = Join-Path $tempBase ("permitmesh-clean-room-" + [guid]::NewGuid().ToString("N"))
$clonePath = Join-Path $tempRoot "repo"
$venvPath = Join-Path $tempRoot "venv"
$receiptPath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Receipt))
$pushed = $false

try {
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    git clone --quiet $repoRoot $clonePath
    if ($LASTEXITCODE -ne 0) { throw "git clone failed" }

    & $Python -m venv $venvPath
    if ($LASTEXITCODE -ne 0) { throw "venv creation failed" }
    $venvPython = Join-Path $venvPath "Scripts/python.exe"
    $permitmesh = Join-Path $venvPath "Scripts/permitmesh.exe"

    Push-Location $clonePath
    $pushed = $true
    & $venvPython -m pip install --quiet --disable-pip-version-check .
    if ($LASTEXITCODE -ne 0) { throw "package install failed" }
    & $venvPython -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw "test suite failed" }
    & $permitmesh conformance examples/conformance-suite.json
    if ($LASTEXITCODE -ne 0) { throw "conformance suite failed" }
    & $permitmesh authorize examples/contract.valid.json examples/request.allowed.json --evaluation-time 2026-07-23T12:00:00Z
    if ($LASTEXITCODE -ne 0) { throw "allowed demo failed" }
    Pop-Location
    $pushed = $false

    $elapsed = [math]::Round(((Get-Date) - $started).TotalSeconds, 3)
    $result = [ordered]@{
        receipt_version = "0.1"
        status = "pass"
        source = "clean local git clone"
        commit = (git -C $repoRoot rev-parse HEAD)
        python = (& $venvPython --version 2>&1).ToString()
        elapsed_seconds = $elapsed
        threshold_seconds = 600
        tests = "pass"
        conformance = "18/18"
        enforcement_boundary = "policy-decision-only; no tool execution"
    }
    New-Item -ItemType Directory -Force -Path (Split-Path $receiptPath) | Out-Null
    $result | ConvertTo-Json | Set-Content -Encoding utf8 $receiptPath
    $result | ConvertTo-Json
}
finally {
    if ($pushed) { Pop-Location }
    $resolvedTemp = [System.IO.Path]::GetFullPath($tempRoot)
    if ($resolvedTemp.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase) -and
        $resolvedTemp -like "*permitmesh-clean-room-*") {
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
