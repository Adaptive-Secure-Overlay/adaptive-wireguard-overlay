[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot
$env:PYTHONPATH = "$ProjectRoot\src"

# Local files, Python stdlib and the installed OpenSSH signature verifier only.
# No sockets, WG, firewall, SSH connection or EVE-NG.
if ($null -eq (Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
    throw 'OpenSSH ssh-keygen with SSHSIG support is required'
}
& python -m json.tool config/wg-overlay.example.json *> $null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& python -m json.tool schemas/eve-result.schema.json *> $null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& python -m json.tool schemas/trust-registry.schema.json *> $null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& python -m unittest discover -s tests -p 'test_*.py' -v
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& python -m wg_handshake_overlay validate
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& python -m wg_handshake_overlay simulate --format json *> $null
exit $LASTEXITCODE
