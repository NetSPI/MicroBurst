# !!! Rewrite this based off of installed Modules (AzureRM vs AZ, AzureAD, MSOL)

Get-ChildItem (Join-Path -Path $PSScriptRoot -ChildPath *.ps1) | ForEach-Object -Process {
    Import-Module $_.FullName
}
