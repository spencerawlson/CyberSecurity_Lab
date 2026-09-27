# Creates a clearly-labelled desktop shortcut for the SAFE training simulation.
#
# This is deliberately the OPPOSITE of a malicious lure:
#   * the shortcut name states it is a SAFE training simulation
#   * it uses a standard Windows shell icon, NOT a disguised one
#   * it points at the honestly-named launcher in this folder
# Run:  powershell -ExecutionPolicy Bypass -File make-shortcut.ps1
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$launcher = Join-Path $here 'RUN-TRAINING-SIMULATION.cmd'
if (-not (Test-Path $launcher)) {
    throw "launcher not found: $launcher"
}

$desktop = [Environment]::GetFolderPath('Desktop')
$linkPath = Join-Path $desktop 'DDoS IR Training Simulation (SAFE).lnk'

$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut($linkPath)
$sc.TargetPath = $launcher
$sc.WorkingDirectory = $here
$sc.Description = 'SAFE DDoS incident-response TRAINING simulation (not an attack tool, loopback only)'
# Standard shell icon (imageres.dll index 2). Chosen precisely because it does
# NOT masquerade as anything else.
$sc.IconLocation = "$env:SystemRoot\System32\imageres.dll,2"
$sc.Save()

Write-Host "Created shortcut:"
Write-Host "  $linkPath"
Write-Host "Icon: standard Windows shell icon (no disguise)."
