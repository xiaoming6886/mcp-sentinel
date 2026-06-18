param([string]$message = "update")
Set-Location $PSScriptRoot

$errors = $false
if (Get-Command ruff -ErrorAction SilentlyContinue) {
    ruff check src/; if ($LASTEXITCODE -ne 0) { $errors = $true }
}
if (Get-Command pytest -ErrorAction SilentlyContinue) {
    pytest -q; if ($LASTEXITCODE -ne 0) { $errors = $true }
}
if ($errors) { Write-Host "Fix errors first" -ForegroundColor Red; exit 1 }

git add -A
git commit -m $message
git -c http.sslVerify=false push
Write-Host "Done!" -ForegroundColor Green
