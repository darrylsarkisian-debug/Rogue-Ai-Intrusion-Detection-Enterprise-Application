<#
  Build the client PDF findings report from the latest demo/scan output.
    powershell -ExecutionPolicy Bypass -File .\run_report.ps1
    powershell -ExecutionPolicy Bypass -File .\run_report.ps1 -Client "Contoso Ltd" -PreparedBy "Darryl Sarkisian"
  -Sample stamps SAMPLE on every page. Use it for anything built from simulated data.
  -Cloud turns on cloud triage (needs ANTHROPIC_API_KEY); default is rules-only.
#>
param(
  [string]$Project = "C:\Users\Darryl\Documents\AI Threat Detection Application\rogue-ai-detection",
  [string]$Client = "Your organization",
  [string]$PreparedBy = "",
  [string]$Period = "",
  [switch]$Sample,
  [switch]$Cloud
)
$ErrorActionPreference = "Continue"
Set-Location $Project

$py = $null
foreach ($cand in @("python", "py")) {
  $c = Get-Command $cand -ErrorAction SilentlyContinue
  if ($c -and $c.Source -notmatch "WindowsApps") { $py = $cand; break }
}
if (-not $py) { Write-Host "Python not found. Install Python 3.10+ and re-run." -ForegroundColor Red; return }

& $py -m pip install -q -r requirements.txt 2>&1 | Out-Null

if (-not (Test-Path "data\proxy_log.csv")) { & $py sim\generate_data.py | Out-Null }
if ($Cloud) { & $py run_demo.py } else { & $py run_demo.py --no-cloud }
if ($LASTEXITCODE -ne 0) { Write-Host "Demo run failed; no report built." -ForegroundColor Red; return }

$stamp = Get-Date -Format "yyyyMMdd-HHmm"
$out = "reports\AI_Exposure_Assessment_$stamp.pdf"
$args2 = @("make_report.py", "--out", $out, "--client", $Client)
if ($PreparedBy) { $args2 += @("--prepared-by", $PreparedBy) }
if ($Period)     { $args2 += @("--period", $Period) }
if ($Sample)     { $args2 += "--sample" }
& $py @args2
if ($LASTEXITCODE -ne 0) { Write-Host "Report build failed (see above)." -ForegroundColor Red; return }

$full = (Resolve-Path $out).Path
Write-Host "Report: $full" -ForegroundColor Green
Start-Process $full
