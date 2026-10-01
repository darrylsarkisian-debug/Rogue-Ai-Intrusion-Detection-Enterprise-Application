<#
  Step 2: push the project to GitHub.
  Requires git installed and you signed in (Git Credential Manager prompts once).
    powershell -ExecutionPolicy Bypass -File .\push_to_github.ps1
#>
param(
  [string]$Project = "C:\Users\Darryl\Documents\AI Threat Detection Application\rogue-ai-detection",
  [string]$Remote = "https://github.com/darrylsarkisian-debug/Rogue-Ai-Intrusion-Detection-Enterprise-Application.git",
  [string]$Message = "Add MVP scaffold: three detectors, triage agent, simulator, tests"
)
$ErrorActionPreference = "Stop"
Set-Location $Project

# Clear stale lock/temp files left by an interrupted git run
Remove-Item -Force -ErrorAction SilentlyContinue ".git\index.lock"
Get-ChildItem .git -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -eq 0 -and $_.Name -match '^tx' } | Remove-Item -Force -ErrorAction SilentlyContinue

if (-not (Test-Path ".git")) {
  git init -b main
  git remote add origin $Remote
} else {
  $current = git remote get-url origin 2>$null
  if (-not $current) { git remote add origin $Remote }
  elseif ($current -ne $Remote) { git remote set-url origin $Remote }
}

git add -A
git diff --cached --quiet
if ($LASTEXITCODE -eq 0) { Write-Host "Nothing new to commit."; exit 0 }

git commit -m $Message
# Pull first in case the repo already has a README/license commit
$ErrorActionPreference = "Continue"   # git writes progress to stderr; don't treat it as failure
git pull origin main --allow-unrelated-histories --no-edit 2>&1 | Out-Null
$ErrorActionPreference = "Stop"
git push --set-upstream origin main
Write-Host "Pushed to $Remote"
