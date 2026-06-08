
# Shared cross-platform helper (Out-GridView replacement)
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath ..\Select-MBItem.ps1)

Get-ChildItem (Join-Path -Path $PSScriptRoot -ChildPath *.ps1) | ForEach-Object -Process {
    Import-Module $_.FullName
}
Write-Host "Imported AzureRM MicroBurst functions"