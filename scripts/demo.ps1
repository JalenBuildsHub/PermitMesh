$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$previousPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = Join-Path $repoRoot "src"

try {
    Push-Location $repoRoot

    Write-Host "1/4 Validate the capability contract"
    python -m permitmesh validate examples\contract.valid.json
    if ($LASTEXITCODE -ne 0) { throw "contract validation failed" }

    Write-Host "`n2/4 Authorize an in-scope edit"
    python -m permitmesh authorize examples\contract.valid.json examples\request.allowed.json --evaluation-time 2026-07-23T12:00:00Z
    if ($LASTEXITCODE -ne 0) { throw "allowed request was denied" }

    Write-Host "`n3/4 Deny an over-scoped deploy"
    python -m permitmesh authorize examples\contract.valid.json examples\request.denied.json --evaluation-time 2026-07-23T12:00:00Z
    if ($LASTEXITCODE -ne 3) { throw "denied request did not return exit code 3" }

    Write-Host "`n4/4 Build an explicitly unsigned Nostr event template"
    python -m permitmesh to-event examples\contract.valid.json --created-at 1784800000
    if ($LASTEXITCODE -ne 0) { throw "event template generation failed" }

    Write-Host "`nPermitMesh demo passed."
}
finally {
    Pop-Location
    $env:PYTHONPATH = $previousPythonPath
}
