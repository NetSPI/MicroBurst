# MicroBurst
A collection of scripts for assessing Microsoft Azure security

# Invoke-EnumerateAzureBlobs.ps1
PS C:\> Get-Help Invoke-EnumerateAzureBlobs

NAME: Invoke-EnumerateAzureBlobs
    
SYNOPSIS: PowerShell function for enumerating public Azure Blobs and Containers.
        
SYNTAX: Invoke-EnumerateAzureBlobs [[-Base] <String>] [[-OutputFile] <String>] [[-Permutations] <String>] [[-Folders] <String>] [[-BingAPIKey] <String>] [<CommonParameters>]
        
DESCRIPTION: The function will check for valid .blob.core.windows.net host names via DNS. 
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
