[CmdletBinding()]
param()

& (Join-Path $PSScriptRoot 'validate-local.ps1')
exit $LASTEXITCODE
