# MicroBurst
A collection of scripts for assessing Microsoft Azure security

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
