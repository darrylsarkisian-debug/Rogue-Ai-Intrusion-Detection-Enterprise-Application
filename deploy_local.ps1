<#
  Step 1: copy the project (and plan PDF) into your local project folder.
  Run from the folder where you saved the downloaded rogue-ai-detection files:
    powershell -ExecutionPolicy Bypass -File .\deploy_local.ps1
#>
param(
  [string]$Source = $PSScriptRoot,
  [string]$Dest = "C:\Users\Darryl\Documents\AI Threat Detection Application"
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $Dest)) { New-Item -ItemType Directory -Path $Dest | Out-Null }

$target = Join-Path $Dest "rogue-ai-detection"
robocopy $Source $target /E /XD __pycache__ .pytest_cache .git /XF *.pyc audit.jsonl /NFL /NDL /NJH /NJS | Out-Null
# robocopy exit codes 0-7 are success
if ($LASTEXITCODE -ge 8) { throw "robocopy failed with code $LASTEXITCODE" }

# Plan PDF, if it sits beside this script, goes to the folder root
Get-ChildItem -Path $Source -Filter "*.pdf" -File -ErrorAction SilentlyContinue |
  ForEach-Object { Copy-Item $_.FullName -Destination $Dest -Force }

Write-Host "Copied to $target"
