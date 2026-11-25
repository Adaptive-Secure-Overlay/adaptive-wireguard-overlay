[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot
$env:PYTHONPATH = "$ProjectRoot\src"

if ($null -eq (Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
    throw 'OpenSSH ssh-keygen with SSHSIG support is required'
}
& python -m unittest discover -s tests -p 'test_trust_registry.py' -v
exit $LASTEXITCODE
