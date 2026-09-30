<#
  Read-only endpoint inventory for Goal 3 (unapproved agents).
  Collects: running processes, listening TCP ports, large model files, GPU load.
  Writes one JSON file the sensor ingests. Changes nothing on the machine.
  Run:  powershell -ExecutionPolicy Bypass -File collect_inventory.ps1 -Out inventory.json
#>
param(
  [string]$Out = "$env:COMPUTERNAME-inventory.json",
  [string[]]$ScanRoots = @("$env:USERPROFILE"),
  [int]$MinMB = 500
)

$procs = Get-CimInstance Win32_Process | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; cmdline = $_.CommandLine }
}

$ports = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Select-Object -ExpandProperty LocalPort -Unique

$ext = @("*.gguf","*.safetensors","*.ggml","*.onnx")
$files = foreach ($root in $ScanRoots) {
  Get-ChildItem -Path $root -Recurse -Include $ext -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -ge ($MinMB * 1MB) } |
    ForEach-Object { [pscustomobject]@{ path = $_.FullName; mb = [int]($_.Length / 1MB) } }
}

$gpu = 0
try {
  $gpu = [int]((Get-Counter '\GPU Engine(*engtype_3D)\Utilization Percentage' -ErrorAction Stop).CounterSamples |
    Measure-Object CookedValue -Sum).Sum
  if ($gpu -gt 100) { $gpu = 100 }
} catch { }

[pscustomobject]@{
  host = $env:COMPUTERNAME
  processes = @($procs)
  listening_ports = @($ports)
  large_files = @($files)
  gpu_percent = $gpu
} | ConvertTo-Json -Depth 5 | Set-Content -Path $Out -Encoding UTF8

Write-Host "Inventory written to $Out"
