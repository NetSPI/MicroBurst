<#
    File: Invoke-AppServicesCMD.ps1
    Author: Josh Magri (@passthehashbrwn), NetSPI - 2021
    Description: PowerShell function for running commands against an App Services host
#>

Function Invoke-AzAppServicesCMD {
<#
    .SYNOPSIS
        Runs a command against an App Services host.
    .DESCRIPTION
        This function will run a command against an App Services host. This can aid in enumerating environment variables for secrets, obtaining Managed Identities tokens at scale, or searching file systems for configuration files.
    .PARAMETER command
        The command to run against the host.
    .PARAMETER appName
        The name of the application to target.
    .PARAMETER username
        The username for connecting to host. The script will attempt to fetch a username from the publishing profile if not provided.
    .PARAMETER password
        The password for connecting to the host. The script will attempt to fetch a password from the publishing profile if not provided.
    .EXAMPLE
        To run against a single host
        PS C:\MicroBurst> Invoke-AzAppServicesCmd -command "dir D:\home" -appName "Target-App"
    .EXAMPLE
        To run against many hosts and store the results
        PS C:\MicroBurst> Get-AzFunctionApp | ForEach-Object {Invoke-AzAppServicesCmd -command "dir D:\home" -appName $_.Name}
        
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
        HelpMessage="The command to run.")]
        [string]$command = "",

        [Parameter(Mandatory=$true,
        HelpMessage="The name of the App to target.")]
        [string]$appName = "",

        [Parameter(Mandatory=$false,
        HelpMessage="The username for connecting to the App Service. The script will attempt to fetch a username from the publishing profile if not provided.")]
        [string]$username = "",

        [Parameter(Mandatory=$false,
        HelpMessage="The password for connecting to the App Service. The script will attempt to fetch a password from the publishing profile if not provided.")]
        [string]$password = ""

    )
    
    $app = Get-AzWebApp -Name $appName 
    if(-Not $app){
        Write-Error "The app $appName does not exist"
        break
    }
    if($app.State -ne "Running"){
        Write-Error "The app must be running to execute commands"
        break
    }
    if($username -eq "" -or $password -eq ""){
        try{
            [xml]$publishingCreds = Get-AzWebAppPublishingProfile -Name $app.Name -ResourceGroupName $app.ResourceGroup
    
            #They should all be the same so we can just grab the first
            if($publishingCreds){
                $username = $publishingCreds.publishData.publishProfile[0].userName
                $password = $publishingCreds.publishData.publishProfile[0].userPWD
            }
        }
        catch{
            Write-Error "$appName - Either no publishing credentials were available or you have insufficient permissions"
            break
        }
    }

    #Need to convert these to a basic authentication header
    $basicHeader = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes((-join($username,":",$password))))

    $commandBody = @{
        "command"=$command;
    }
        
    $cmdReq = Invoke-WebRequest -Verbose:$false -Method POST -Uri (-join ("https://", $app.Name, ".scm.azurewebsites.net/api/command")) -Headers @{Authorization="Basic $basicHeader"} -Body ($commandBody | ConvertTo-Json) -ContentType "application/json"
    $cmdResult = $cmdReq.Content | ConvertFrom-Json

    $cmdResult

}

