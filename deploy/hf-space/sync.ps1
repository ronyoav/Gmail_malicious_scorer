<#
.SYNOPSIS
    Publishes the backend to a Hugging Face Space (Docker SDK).

.DESCRIPTION
    Clones the Space repo into a temp directory, copies the backend package,
    the Dockerfile and the Space card, then commits and pushes.

    Git asks for credentials on the first push: username = your HF username,
    password = a Hugging Face access token with write permission
    (https://huggingface.co/settings/tokens).

.EXAMPLE
    ./sync.ps1 -Space ronyoav/email-security-scorer
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Space,

    [string]$Message = "Deploy backend"
)

$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $here "..\..")
$workDir = Join-Path $env:TEMP "hf-space-sync"

if (Test-Path $workDir) { Remove-Item -Recurse -Force $workDir }

git clone "https://huggingface.co/spaces/$Space" $workDir
if ($LASTEXITCODE -ne 0) { throw "Clone failed. Does the Space $Space exist?" }

# Backend package: wipe first so deleted files do not linger in the Space
$targetBackend = Join-Path $workDir "backend"
if (Test-Path $targetBackend) { Remove-Item -Recurse -Force $targetBackend }
Copy-Item (Join-Path $repoRoot "backend") $targetBackend -Recurse
Get-ChildItem $targetBackend -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force

Copy-Item (Join-Path $here "Dockerfile") (Join-Path $workDir "Dockerfile") -Force
Copy-Item (Join-Path $here "README.md") (Join-Path $workDir "README.md") -Force

git -C $workDir add -A
git -C $workDir commit -m $Message
if ($LASTEXITCODE -ne 0) { Write-Host "Nothing to commit — Space already up to date."; exit 0 }

git -C $workDir push
if ($LASTEXITCODE -ne 0) { throw "Push failed — check your Hugging Face write token." }

Write-Host ""
Write-Host "Pushed. Build progress: https://huggingface.co/spaces/$Space"
Write-Host "Endpoint once built:   https://$($Space.Replace('/', '-')).hf.space/health"
